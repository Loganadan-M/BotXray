import { clamp, round } from '../utils/common.js';

function categorizeSignals(signals) {
  const groups = {
    automation: [],
    fingerprint: [],
    consistency: [],
    behavior: [],
    environment: [],
    integrity: []
  };

  signals.forEach(signal => {
    if (!groups[signal.category]) groups[signal.category] = [];
    groups[signal.category].push(signal);
  });

  return groups;
}

function scoreCategory(signals, categoryWeight) {
  let max = 0;
  let hit = 0;

  signals.forEach(signal => {
    if (signal.state === 'unavailable') return;
    const weighted = signal.weight * categoryWeight;
    max += weighted;

    if (signal.value && signal.state === 'suspicious') {
      const confidenceFactor = Math.max(0.3, (signal.confidence || 50) / 100);
      hit += weighted * confidenceFactor;
    }
  });

  const normalized = max > 0 ? (hit / max) * 100 : 0;
  return {
    max,
    hit,
    score100: round(normalized, 2)
  };
}

function applyCriticalEscalation(score100, criticalHits, floors = []) {
  if (!Array.isArray(floors) || floors.length === 0) return score100;

  let score = score100;
  const orderedFloors = floors
    .filter(rule => typeof rule?.minCriticalHits === 'number' && typeof rule?.minScore === 'number')
    .sort((a, b) => b.minCriticalHits - a.minCriticalHits);

  for (let i = 0; i < orderedFloors.length; i += 1) {
    const rule = orderedFloors[i];
    if (criticalHits >= rule.minCriticalHits && score < rule.minScore) {
      score = rule.minScore;
      break;
    }
  }

  return score;
}

function applyClusterEscalation(score100, signals, clusterRules = []) {
  if (!Array.isArray(clusterRules) || clusterRules.length === 0) {
    return { score100, appliedRules: [] };
  }

  const suspiciousKeySet = new Set(
    signals
      .filter(signal => signal.value && signal.state === 'suspicious')
      .map(signal => signal.key)
  );

  let score = score100;
  const appliedRules = [];

  clusterRules.forEach(rule => {
    if (!rule || typeof rule.minScore !== 'number') return;

    const requireAll = Array.isArray(rule.requireAllKeys) ? rule.requireAllKeys : [];
    const requireAny = Array.isArray(rule.requireAnyKeys) ? rule.requireAnyKeys : [];
    const allOk = requireAll.every(key => suspiciousKeySet.has(key));
    const anyOk = requireAny.length === 0 || requireAny.some(key => suspiciousKeySet.has(key));

    if (allOk && anyOk && score < rule.minScore) {
      score = rule.minScore;
      appliedRules.push(rule.key || 'unnamed-cluster-rule');
    }
  });

  return { score100: score, appliedRules };
}

function applyConsistencyReward(score100, weakChecks, policy, context) {
  const consistentChecks = weakChecks.filter(check => check.ok && check.state !== 'unavailable').length;
  const suspiciousSignals = context?.suspiciousSignals || [];
  const hardSuspiciousCount = context?.hardSuspiciousCount ?? suspiciousSignals.filter(signal => signal.severity === 'hard').length;
  const suspiciousCount = context?.suspiciousCount ?? suspiciousSignals.length;
  const criticalHits = context?.criticalHits ?? 0;

  const withinSuspiciousLimit = suspiciousCount <= (policy.maxSuspiciousSignals ?? Number.POSITIVE_INFINITY);
  const withinHardLimit = hardSuspiciousCount <= (policy.maxHardSuspiciousSignals ?? Number.POSITIVE_INFINITY);
  const criticalAllowed = policy.skipWhenCriticalHits ? criticalHits === 0 : true;

  if (consistentChecks >= policy.minConsistentChecks && withinSuspiciousLimit && withinHardLimit && criticalAllowed) {
    return {
      score100: Math.max(0, score100 - policy.scoreReduction),
      rewarded: true,
      consistentChecks,
      skippedReason: null
    };
  }

  let skippedReason = null;
  if (consistentChecks < policy.minConsistentChecks) skippedReason = 'insufficient-consistent-checks';
  else if (!withinSuspiciousLimit) skippedReason = 'too-many-suspicious-signals';
  else if (!withinHardLimit) skippedReason = 'hard-suspicious-signals-present';
  else if (!criticalAllowed) skippedReason = 'critical-signals-present';

  return {
    score100,
    rewarded: false,
    consistentChecks,
    skippedReason
  };
}

function resolveRiskAction(score100, actionMapping) {
  for (let i = 0; i < actionMapping.length; i += 1) {
    const rule = actionMapping[i];
    if (score100 >= rule.minScore) return { riskLabel: rule.riskLabel, action: rule.action };
  }

  const fallback = actionMapping[actionMapping.length - 1];
  return { riskLabel: fallback.riskLabel, action: fallback.action };
}

function computeConfidence(signals, criticalHits) {
  const available = signals.filter(signal => signal.state !== 'unavailable');
  const suspicious = available.filter(signal => signal.value);
  const coverage = available.length / Math.max(signals.length, 1);
  const avgSignalConfidence = suspicious.length
    ? suspicious.reduce((acc, signal) => acc + signal.confidence, 0) / suspicious.length
    : 50;

  const confidence = 35 + (coverage * 30) + (suspicious.length * 1.2) + (criticalHits * 8) + (avgSignalConfidence * 0.18);
  return clamp(Math.round(confidence), 20, 99);
}

function topSignalExplanations(signals, limit = 8) {
  return signals
    .filter(signal => signal.value)
    .sort((a, b) => (b.weight * b.confidence) - (a.weight * a.confidence))
    .slice(0, limit)
    .map(signal => {
      const evidenceSnippet = typeof signal.evidence === 'string'
        ? signal.evidence
        : signal.evidence && Array.isArray(signal.evidence)
          ? signal.evidence.slice(0, 3).join(', ')
          : signal.evidence && typeof signal.evidence === 'object'
            ? JSON.stringify(signal.evidence).slice(0, 180)
            : 'n/a';

      return `${signal.label} (${signal.category}, ${signal.severity}, w=${signal.weight}, c=${signal.confidence}) evidence=${evidenceSnippet}`;
    });
}

export function computeRiskEngine({ signals, weakChecks, config }) {
  const normalizedWeakChecks = Array.isArray(weakChecks) ? weakChecks : [];
  const grouped = categorizeSignals(signals);
  const categoryBreakdown = {};
  const suspiciousSignals = signals.filter(signal => signal.value && signal.state === 'suspicious');
  const hardSuspiciousCount = suspiciousSignals.filter(signal => signal.severity === 'hard').length;

  let globalMax = 0;
  let globalHit = 0;

  Object.entries(grouped).forEach(([category, categorySignals]) => {
    const categoryWeight = config.scoring.categoryWeights[category] ?? 1;
    const categoryScore = scoreCategory(categorySignals, categoryWeight);
    categoryBreakdown[category] = categoryScore.score100;
    globalMax += categoryScore.max;
    globalHit += categoryScore.hit;
  });

  let score100 = globalMax > 0 ? (globalHit / globalMax) * 100 : 0;
  const criticalHits = signals.filter(signal => signal.value && config.scoring.criticalSignalKeys.includes(signal.key)).length;
  score100 = applyCriticalEscalation(score100, criticalHits, config.scoring.criticalEscalationFloors);

  const reward = applyConsistencyReward(score100, normalizedWeakChecks, config.scoring.consistencyReward, {
    suspiciousSignals,
    hardSuspiciousCount,
    suspiciousCount: suspiciousSignals.length,
    criticalHits
  });
  score100 = reward.score100;

  const clusterEscalation = applyClusterEscalation(score100, signals, config.scoring.clusterEscalationRules);
  score100 = clusterEscalation.score100;

  score100 = clamp(Math.round(score100), 0, 100);

  const botScore = clamp(Math.round(score100 / config.scoreToBotScoreDivisor), 0, config.maxBotScore);
  const risk = resolveRiskAction(score100, config.scoring.actionMapping);
  const confidence = computeConfidence(signals, criticalHits);
  const explanations = topSignalExplanations(signals);

  return {
    score100,
    botScore,
    confidence,
    riskLabel: risk.riskLabel,
    action: risk.action,
    categoryBreakdown,
    criticalHits,
    consistencyRewardApplied: reward.rewarded,
    consistentChecks: reward.consistentChecks,
    consistencyRewardSkippedReason: reward.skippedReason,
    appliedClusterEscalations: clusterEscalation.appliedRules,
    explanations
  };
}
