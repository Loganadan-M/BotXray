import { hashString, round } from '../utils/common.js';

function normalizeEvidence(evidence) {
  if (evidence === undefined) return null;
  if (evidence === null) return null;
  if (typeof evidence === 'string' || typeof evidence === 'number' || typeof evidence === 'boolean') return evidence;
  if (Array.isArray(evidence)) return evidence.slice(0, 20);

  if (typeof evidence === 'object') {
    const normalized = {};
    Object.entries(evidence).forEach(([key, value]) => {
      if (Array.isArray(value)) {
        normalized[key] = value.slice(0, 20);
      } else if (value && typeof value === 'object') {
        normalized[key] = JSON.parse(JSON.stringify(value, (_, nested) => {
          if (Array.isArray(nested)) return nested.slice(0, 20);
          return nested;
        }));
      } else {
        normalized[key] = value;
      }
    });
    return normalized;
  }

  return String(evidence);
}

export function normalizeSignals(signals) {
  return signals.map(signal => ({
    ...signal,
    evidence: normalizeEvidence(signal.evidence)
  }));
}

export function buildSummary({ signals, weakChecks, probes, telemetry, runtimeInfo }) {
  const suspiciousSignals = signals.filter(signal => signal.value);
  const unavailableSignals = signals.filter(signal => signal.state === 'unavailable').length;
  const hardHits = suspiciousSignals.filter(signal => signal.severity === 'hard').length;
  const softHits = suspiciousSignals.filter(signal => signal.severity === 'soft').length;

  return {
    strongHits: suspiciousSignals.length,
    strongTotal: signals.length,
    hardHits,
    softHits,
    weakMismatchCount: weakChecks.filter(check => !check.ok && check.state !== 'unavailable').length,
    weakUnavailableCount: weakChecks.filter(check => check.state === 'unavailable').length,
    weakTotal: weakChecks.length,
    unavailableSignals,
    telemetry,
    probes,
    runtimeInfo
  };
}

export function computeResultChecksum(payload) {
  const serialized = JSON.stringify({
    runId: payload.runId,
    timestamp: payload.timestamp,
    score100: payload.score100,
    riskLabel: payload.riskLabel,
    signals: payload.signals.map(signal => ({ key: signal.key, value: signal.value, state: signal.state })),
    weakChecks: payload.weakChecks.map(check => ({ key: check.key, ok: check.ok, state: check.state }))
  });

  return hashString(serialized);
}

export function humanReadableSummary(result) {
  const top = result.signals
    .filter(signal => signal.value)
    .sort((a, b) => (b.weight * b.confidence) - (a.weight * a.confidence))
    .slice(0, 3)
    .map(signal => signal.label);

  return {
    headline: `${result.riskLabel} risk (${result.action})`,
    detail: top.length
      ? `Primary suspicious signals: ${top.join('; ')}`
      : 'No high-confidence suspicious signals were triggered.',
    elapsedMs: result.elapsedMs,
    score100: result.score100,
    confidence: result.confidence,
    consistencyRewardApplied: !!result.summary?.runtimeInfo?.consistencyRewardApplied,
    categoryBreakdown: Object.fromEntries(
      Object.entries(result.categoryBreakdown || {}).map(([key, value]) => [key, round(value, 2)])
    )
  };
}
