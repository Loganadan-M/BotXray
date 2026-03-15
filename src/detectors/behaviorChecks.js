import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';
import { mean, stdDev, round } from '../utils/common.js';

function sumCounts(counts) {
  return Object.values(counts).reduce((acc, value) => acc + value, 0);
}

function buildSignal(key, label, value, evidence, state = STATES.OK) {
  const rule = resolveRule(key);
  return createDetectorResult({
    key,
    label,
    value,
    evidence,
    category: rule.category,
    severity: rule.severity,
    weight: rule.weight,
    confidence: rule.confidence,
    state: value ? STATES.SUSPICIOUS : state
  });
}

export function initBehaviorTracker() {
  const state = {
    startedAt: performance.now(),
    firstInteractionAt: null,
    lastEventAt: null,
    counts: {
      mousemove: 0,
      pointerdown: 0,
      wheel: 0,
      keydown: 0,
      touchstart: 0,
      focus: 0,
      blur: 0,
      visibilitychange: 0
    },
    eventTimes: [],
    wheelTimes: [],
    clickTimes: [],
    pointerSamples: []
  };

  const register = type => {
    state.counts[type] += 1;
    const now = performance.now();
    state.lastEventAt = now;
    state.eventTimes.push(now);
    if (!state.firstInteractionAt && !['focus', 'blur', 'visibilitychange'].includes(type)) {
      state.firstInteractionAt = now;
    }
  };

  const onMouseMove = event => {
    register('mousemove');
    state.pointerSamples.push({ x: event.clientX, y: event.clientY, t: performance.now() });
    if (state.pointerSamples.length > 180) state.pointerSamples.shift();
  };

  const onPointerDown = () => {
    register('pointerdown');
    state.clickTimes.push(performance.now());
    if (state.clickTimes.length > 80) state.clickTimes.shift();
  };

  const onWheel = () => {
    register('wheel');
    state.wheelTimes.push(performance.now());
    if (state.wheelTimes.length > 120) state.wheelTimes.shift();
  };

  const onKeyDown = () => register('keydown');
  const onTouchStart = () => register('touchstart');
  const onFocus = () => register('focus');
  const onBlur = () => register('blur');
  const onVisibility = () => register('visibilitychange');

  window.addEventListener('mousemove', onMouseMove, { passive: true });
  window.addEventListener('pointerdown', onPointerDown, { passive: true });
  window.addEventListener('wheel', onWheel, { passive: true });
  window.addEventListener('keydown', onKeyDown, { passive: true });
  window.addEventListener('touchstart', onTouchStart, { passive: true });
  window.addEventListener('focus', onFocus, { passive: true });
  window.addEventListener('blur', onBlur, { passive: true });
  document.addEventListener('visibilitychange', onVisibility, { passive: true });

  return {
    state,
    stop() {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('wheel', onWheel);
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('touchstart', onTouchStart);
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('blur', onBlur);
      document.removeEventListener('visibilitychange', onVisibility);
    }
  };
}

function computePointerMetrics(samples) {
  if (!samples || samples.length < 3) {
    return {
      avgVelocity: 0,
      avgAcceleration: 0,
      straightLineRatio: 0,
      pathLength: 0
    };
  }

  const velocities = [];
  let pathLength = 0;

  for (let i = 1; i < samples.length; i += 1) {
    const previous = samples[i - 1];
    const current = samples[i];
    const dt = current.t - previous.t;
    if (dt <= 0) continue;

    const dx = current.x - previous.x;
    const dy = current.y - previous.y;
    const distance = Math.sqrt(dx * dx + dy * dy);
    pathLength += distance;
    velocities.push(distance / dt);
  }

  const accelerations = [];
  for (let i = 1; i < velocities.length; i += 1) {
    accelerations.push(Math.abs(velocities[i] - velocities[i - 1]));
  }

  const first = samples[0];
  const last = samples[samples.length - 1];
  const straightDistance = Math.sqrt((last.x - first.x) ** 2 + (last.y - first.y) ** 2);

  return {
    avgVelocity: round(mean(velocities), 6),
    avgAcceleration: round(mean(accelerations), 6),
    straightLineRatio: pathLength > 0 ? round(straightDistance / pathLength, 6) : 0,
    pathLength: round(pathLength, 2)
  };
}

function computeEventCadence(timestamps) {
  if (!Array.isArray(timestamps) || timestamps.length < 2) {
    return {
      intervals: [],
      avgInterval: 0,
      stdInterval: 0,
      burstiness: 0
    };
  }

  const intervals = [];
  for (let i = 1; i < timestamps.length; i += 1) {
    intervals.push(timestamps[i] - timestamps[i - 1]);
  }

  const avg = mean(intervals);
  const std = stdDev(intervals);
  const burstiness = (std + avg) > 0 ? round((std - avg) / (std + avg), 6) : 0;

  return {
    intervals,
    avgInterval: round(avg, 4),
    stdInterval: round(std, 4),
    burstiness
  };
}

function computeScrollBurst(wheelTimes) {
  const cadence = computeEventCadence(wheelTimes);
  const quickIntervals = cadence.intervals.filter(value => value < 40).length;
  const ratio = cadence.intervals.length ? quickIntervals / cadence.intervals.length : 0;

  return {
    ...cadence,
    quickIntervals,
    quickRatio: round(ratio, 4)
  };
}

function buildBehaviorSummary(state, behaviorConfig) {
  const now = performance.now();
  const dwellTimeMs = now - state.startedAt;
  const timeToFirstInteractionMs = state.firstInteractionAt ? state.firstInteractionAt - state.startedAt : null;
  const totalEvents = sumCounts(state.counts);

  const pointerMetrics = computePointerMetrics(state.pointerSamples);
  const eventCadence = computeEventCadence(state.eventTimes);
  const clickCadence = computeEventCadence(state.clickTimes);
  const scrollCadence = computeScrollBurst(state.wheelTimes);

  const idleGaps = [];
  for (let i = 1; i < state.eventTimes.length; i += 1) {
    const gap = state.eventTimes[i] - state.eventTimes[i - 1];
    if (gap > 800) idleGaps.push(round(gap, 2));
  }

  const noHumanInteraction = dwellTimeMs > behaviorConfig.suspiciousNoInteractionMs && totalEvents === 0;

  const entropyScore = totalEvents === 0
    ? 0
    : Object.values(state.counts)
      .filter(count => count > 0)
      .length / Object.keys(state.counts).length;

  const lowInteractionEntropy = totalEvents > 0
    && totalEvents < behaviorConfig.minimumEntropyEvents
    && entropyScore < 0.35;

  const suspiciousMousePattern = state.pointerSamples.length >= 10
    && pointerMetrics.straightLineRatio > behaviorConfig.straightLineRatioThreshold
    && pointerMetrics.avgAcceleration < behaviorConfig.lowVelocityThreshold;

  const suspiciousClickCadence = state.clickTimes.length >= 3
    && clickCadence.stdInterval < 20
    && clickCadence.avgInterval > 0;

  const suspiciousScrollBurst = state.wheelTimes.length >= 8
    && scrollCadence.quickRatio > 0.9;

  return {
    dwellTimeMs: round(dwellTimeMs, 2),
    timeToFirstInteractionMs: timeToFirstInteractionMs === null ? null : round(timeToFirstInteractionMs, 2),
    totalEvents,
    counts: { ...state.counts },
    entropyScore: round(entropyScore, 4),
    pointerMetrics,
    eventCadence: {
      avgInterval: eventCadence.avgInterval,
      stdInterval: eventCadence.stdInterval,
      burstiness: eventCadence.burstiness
    },
    clickCadence: {
      avgInterval: clickCadence.avgInterval,
      stdInterval: clickCadence.stdInterval,
      burstiness: clickCadence.burstiness
    },
    scrollBurst: {
      avgInterval: scrollCadence.avgInterval,
      stdInterval: scrollCadence.stdInterval,
      burstiness: scrollCadence.burstiness,
      quickRatio: scrollCadence.quickRatio
    },
    idleGaps: idleGaps.slice(-20),
    flags: {
      noHumanInteraction,
      lowInteractionEntropy,
      suspiciousMousePattern,
      suspiciousClickCadence,
      suspiciousScrollBurst
    }
  };
}

function normalizeRunContext(runContext) {
  return {
    triggerType: runContext?.triggerType || 'unknown',
    userActivation: {
      isActive: !!runContext?.userActivation?.isActive,
      hasBeenActive: !!runContext?.userActivation?.hasBeenActive
    },
    visibilityState: runContext?.visibilityState || 'unknown',
    hasFocus: typeof runContext?.hasFocus === 'boolean' ? runContext.hasFocus : null,
    scriptedInvocationStack: !!runContext?.scriptedInvocationStack,
    invocationMeta: runContext?.invocationMeta || {}
  };
}

function addRunContextFlags(summary, behaviorConfig, runContext) {
  const ctx = normalizeRunContext(runContext);
  const noUserActivation = !ctx.userActivation.isActive && !ctx.userActivation.hasBeenActive;
  const noInteractionEvents = summary.totalEvents === 0;
  const externalProgrammatic = ctx.triggerType === 'programmatic' || ctx.triggerType === 'external-script';
  const minDwell = Number(behaviorConfig?.programmaticNoActivationMinDwellMs || 250);
  const programmaticNoActivation = externalProgrammatic
    && noUserActivation
    && noInteractionEvents
    && summary.dwellTimeMs >= minDwell;
  const scriptedInvocationStack = !!ctx.scriptedInvocationStack;

  return {
    ...summary,
    runContext: ctx,
    flags: {
      ...summary.flags,
      programmaticNoActivation,
      scriptedInvocationStack
    }
  };
}

export function runBehaviorChecks({ trackerState, behaviorConfig, runContext }) {
  const baseSummary = buildBehaviorSummary(trackerState, behaviorConfig);
  const summary = addRunContextFlags(baseSummary, behaviorConfig, runContext);

  const signals = [
    buildSignal('noHumanInteraction', 'No interaction events observed', summary.flags.noHumanInteraction, summary),
    buildSignal('lowInteractionEntropy', 'Interaction pattern has low entropy', summary.flags.lowInteractionEntropy, summary),
    buildSignal('suspiciousMousePattern', 'Mouse movement appears overly synthetic', summary.flags.suspiciousMousePattern, summary.pointerMetrics),
    buildSignal('suspiciousClickCadence', 'Click cadence appears perfectly periodic', summary.flags.suspiciousClickCadence, summary.clickCadence),
    buildSignal('suspiciousScrollBurst', 'Scroll events appear overly bursty', summary.flags.suspiciousScrollBurst, summary.scrollBurst),
    buildSignal(
      'programmaticNoActivation',
      'Detection invoked programmatically with zero user activation',
      summary.flags.programmaticNoActivation,
      {
        triggerType: summary.runContext.triggerType,
        userActivation: summary.runContext.userActivation,
        totalEvents: summary.totalEvents,
        dwellTimeMs: summary.dwellTimeMs
      }
    ),
    buildSignal(
      'scriptedInvocationStack',
      'Invocation stack looks script-evaluated/injected',
      summary.flags.scriptedInvocationStack,
      {
        triggerType: summary.runContext.triggerType,
        invocationMeta: summary.runContext.invocationMeta
      }
    )
  ];

  return {
    signals,
    telemetry: summary
  };
}
