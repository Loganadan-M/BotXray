import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { mean, stdDev, round } from '../utils/common.js';

/**
 * Extended Behavioral Analysis Module
 * Detects sophisticated behavioral evasion including:
 * - Form-filling patterns
 * - Long-term scroll behavior
 * - Click-to-navigation timing
 * - Resource fetch patterns
 * - Mouse acceleration curves
 * - Context switching behavior
 */

let behaviorExtendedState = {
  formInteractions: [],
  focusHistory: [],
  scrollSessions: [],
  clickNavigationPairs: [],
  resourceLoadTimes: [],
  contextSwitches: [],
  startTime: performance.now(),
  initialized: false
};

function initExtendedBehaviorTracking() {
  if (behaviorExtendedState.initialized) return;

  try {
    // Track input/form interactions
    const onInputFocus = (e) => {
      if (e.target?.tagName === 'INPUT' || e.target?.tagName === 'TEXTAREA') {
        behaviorExtendedState.focusHistory.push({
          type: 'focus',
          time: performance.now(),
          fieldType: e.target.type || 'text'
        });
      }
    };

    const onInputChange = (e) => {
      if (e.target?.tagName === 'INPUT' || e.target?.tagName === 'TEXTAREA') {
        const lastFocus = behaviorExtendedState.focusHistory[behaviorExtendedState.focusHistory.length - 1];
        const focusDelay = lastFocus ? performance.now() - lastFocus.time : 0;

        behaviorExtendedState.formInteractions.push({
          type: 'input-change',
          time: performance.now(),
          focusDelay,
          fieldType: e.target.type || 'text'
        });
      }
    };

    // Track scroll patterns with time windows
    const onScroll = () => {
      const now = performance.now();
      const lastScroll = behaviorExtendedState.scrollSessions[behaviorExtendedState.scrollSessions.length - 1];

      if (lastScroll && now - lastScroll.lastTime > 500) {
        // New scroll session (gap > 500ms)
        behaviorExtendedState.scrollSessions.push({
          startTime: now,
          lastTime: now,
          eventCount: 1,
          totalDistance: 0
        });
      } else if (behaviorExtendedState.scrollSessions.length === 0) {
        behaviorExtendedState.scrollSessions.push({
          startTime: now,
          lastTime: now,
          eventCount: 1,
          totalDistance: 0
        });
      } else {
        behaviorExtendedState.scrollSessions[behaviorExtendedState.scrollSessions.length - 1].eventCount++;
        behaviorExtendedState.scrollSessions[behaviorExtendedState.scrollSessions.length - 1].lastTime = now;
      }
    };

    // Track navigation triggered by clicks
    const onClickBeforeNav = () => {
      behaviorExtendedState.clickNavigationPairs.push({
        clickTime: performance.now(),
        prevResourceCount: performance.getEntriesByType?.('resource')?.length || 0
      });
    };

    // Track resource loading
    const observeResources = () => {
      try {
        const resources = performance.getEntriesByType?.('resource') || [];
        resources.forEach(resource => {
          if (resource.duration && !behaviorExtendedState.resourceLoadTimes.some(r => r.name === resource.name)) {
            behaviorExtendedState.resourceLoadTimes.push({
              name: resource.name,
              duration: resource.duration,
              size: resource.transferSize || 0,
              timestamp: performance.now()
            });
          }
        });
      } catch (e) {
        // Ignore
      }
    };

    // Track context switches
    const onVisibilityChange = () => {
      behaviorExtendedState.contextSwitches.push({
        time: performance.now(),
        visible: document.visibilityState === 'visible',
        hasFocus: document.hasFocus?.()
      });
    };

    window.addEventListener('focus', onInputFocus, { passive: true });
    window.addEventListener('input', onInputChange, { passive: true });
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('click', onClickBeforeNav, { passive: true });
    window.addEventListener('visibilitychange', onVisibilityChange, { passive: true });

    // Periodically observe resources
    setInterval(observeResources, 2000);

    behaviorExtendedState.initialized = true;
  } catch (err) {
    // Ignore initialization errors
  }
}

function analyzeFormFillingPatterns() {
  const signals = [];

  if (behaviorExtendedState.formInteractions.length === 0) {
    return { signals, evidence: { reason: 'no-form-interactions' } };
  }

  const focusToChangeDelays = [];
  behaviorExtendedState.formInteractions.forEach(interaction => {
    if (interaction.focusDelay !== undefined && interaction.focusDelay > 0) {
      focusToChangeDelays.push(interaction.focusDelay);
    }
  });

  if (focusToChangeDelays.length === 0) {
    return { signals, evidence: { reason: 'no-focus-change-pairs' } };
  }

  const avgDelay = mean(focusToChangeDelays);
  const stdDevDelay = stdDev(focusToChangeDelays);

  const evidence = {
    interactionCount: behaviorExtendedState.formInteractions.length,
    focusToChangeDelayMean: round(avgDelay, 2),
    focusToChangeDelayStd: round(stdDevDelay, 2),
    delays: focusToChangeDelays.slice(0, 10)
  };

  // Bots often have zero or extremely consistent delays
  if (stdDevDelay < 5 && focusToChangeDelays.length >= 3) {
    signals.push({
      key: 'suspiciousFormFillingCadence',
      label: 'Suspicious Form-Filling Cadence',
      confidence: 62,
      severity: 'soft',
      weight: 5
    });
  }

  // Bots fill forms instantly (delay < 50ms)
  const instantFills = focusToChangeDelays.filter(d => d < 50).length;
  if (instantFills >= focusToChangeDelays.length * 0.7) {
    signals.push({
      key: 'instantFormFilling',
      label: 'Instant Form Filling (No Typing Delay)',
      confidence: 68,
      severity: 'soft',
      weight: 6
    });
  }

  return { signals, evidence };
}

function analyzeScrollPatterns() {
  const signals = [];

  if (behaviorExtendedState.scrollSessions.length === 0) {
    return { signals, evidence: { reason: 'no-scroll-sessions' } };
  }

  const scrollSessionDurations = behaviorExtendedState.scrollSessions.map(
    s => s.lastTime - s.startTime
  );

  const avgDuration = mean(scrollSessionDurations);
  const avgEventCount = mean(behaviorExtendedState.scrollSessions.map(s => s.eventCount));

  const evidence = {
    sessionCount: behaviorExtendedState.scrollSessions.length,
    avgSessionDuration: round(avgDuration, 2),
    avgEventsPerSession: round(avgEventCount, 2),
    durationVariance: round(stdDev(scrollSessionDurations), 2)
  };

  // Bots often have regular, short scroll bursts
  if (evidence.avgSessionDuration < 200 && behaviorExtendedState.scrollSessions.length >= 2) {
    signals.push({
      key: 'suspiciousScrollSessionDuration',
      label: 'Suspiciously Short Scroll Sessions',
      confidence: 58,
      severity: 'soft',
      weight: 4
    });
  }

  // Calculate scroll events per second during sessions
  const eventRates = behaviorExtendedState.scrollSessions.map(
    s => s.eventCount / Math.max((s.lastTime - s.startTime) / 1000, 0.1)
  );

  const highRateSessions = eventRates.filter(rate => rate > 20).length;
  if (highRateSessions > behaviorExtendedState.scrollSessions.length * 0.5) {
    signals.push({
      key: 'excessiveScrollEventRate',
      label: 'Excessive Scroll Event Rate',
      confidence: 62,
      severity: 'soft',
      weight: 5
    });
  }

  return { signals, evidence };
}

function analyzeClickNavigationTiming() {
  const signals = [];

  if (behaviorExtendedState.clickNavigationPairs.length === 0) {
    return { signals, evidence: { reason: 'no-click-navigation-pairs' } };
  }

  const navigationDelays = [];
  behaviorExtendedState.clickNavigationPairs.forEach(pair => {
    // Measure if new resources were loaded after click
    const resourcesAfter = performance.getEntriesByType?.('resource')?.length || 0;
    const resourcesLoaded = resourcesAfter - pair.prevResourceCount;
    if (resourcesLoaded > 0) {
      navigationDelays.push({
        clickTime: pair.clickTime,
        resourcesTriggered: resourcesLoaded
      });
    }
  });

  if (navigationDelays.length === 0) {
    return { signals, evidence: { reason: 'no-resource-load-correlation' } };
  }

  const evidence = {
    clickCount: behaviorExtendedState.clickNavigationPairs.length,
    navigationsTriggered: navigationDelays.length,
    correlationRate: round((navigationDelays.length / behaviorExtendedState.clickNavigationPairs.length) * 100, 1)
  };

  // Bots might trigger navigation too frequently or too perfectly
  if (evidence.correlationRate === 100 && navigationDelays.length >= 3) {
    signals.push({
      key: 'perfectClickNavigationCorrelation',
      label: 'Perfect Click-Navigation Correlation',
      confidence: 65,
      severity: 'soft',
      weight: 5
    });
  }

  return { signals, evidence };
}

function analyzeResourceLoadPatterns() {
  const signals = [];

  if (behaviorExtendedState.resourceLoadTimes.length === 0) {
    return { signals, evidence: { reason: 'no-resources-loaded' } };
  }

  const durations = behaviorExtendedState.resourceLoadTimes.map(r => r.duration);
  const avgDuration = mean(durations);
  const stdDevDuration = stdDev(durations);

  const evidence = {
    resourceCount: behaviorExtendedState.resourceLoadTimes.length,
    avgLoadTime: round(avgDuration, 2),
    loadTimeVariance: round(stdDevDuration, 2),
    totalSize: behaviorExtendedState.resourceLoadTimes.reduce((a, r) => a + r.size, 0)
  };

  // Check for suspiciously consistent load times (bot simulation)
  if (stdDevDuration < avgDuration * 0.1 && durations.length >= 5) {
    signals.push({
      key: 'suspiciousResourceLoadTimingConsistency',
      label: 'Suspicious Resource Load Timing Consistency',
      confidence: 60,
      severity: 'soft',
      weight: 4
    });
  }

  // Check for suspiciously fast loading (cached/mocked)
  const fastLoads = durations.filter(d => d < 50).length;
  if (fastLoads >= durations.length * 0.8) {
    signals.push({
      key: 'suspiciouslyFastResourceLoading',
      label: 'Suspiciously Fast Resource Loading',
      confidence: 58,
      severity: 'soft',
      weight: 4
    });
  }

  return { signals, evidence };
}

function analyzeContextSwitching() {
  const signals = [];

  if (behaviorExtendedState.contextSwitches.length === 0) {
    return { signals, evidence: { reason: 'no-context-switches' } };
  }

  const hiddenTime = behaviorExtendedState.contextSwitches
    .filter(s => !s.visible)
    .reduce((acc, s, i, arr) => {
      const nextSwitch = arr[i + 1];
      if (nextSwitch) {
        return acc + (nextSwitch.time - s.time);
      }
      return acc;
    }, 0);

  const totalTime = behaviorExtendedState.contextSwitches[behaviorExtendedState.contextSwitches.length - 1].time -
                   behaviorExtendedState.contextSwitches[0].time;

  const evidence = {
    switchCount: behaviorExtendedState.contextSwitches.length,
    hiddenTime: round(hiddenTime, 2),
    totalTime: round(totalTime, 2),
    hiddenPercentage: round((hiddenTime / totalTime) * 100, 1)
  };

  // Bots often keep tab hidden for unnecessary amounts
  if (evidence.hiddenPercentage > 70) {
    signals.push({
      key: 'excessiveTabHiddenTime',
      label: 'Excessive Tab Hidden Time',
      confidence: 64,
      severity: 'soft',
      weight: 5
    });
  }

  return { signals, evidence };
}

function analyzeMouseAccelerationCurves(pointerSamples) {
  const signals = [];

  if (!Array.isArray(pointerSamples) || pointerSamples.length < 5) {
    return { signals, evidence: { reason: 'insufficient-samples' } };
  }

  // Calculate velocities and accelerations
  const velocities = [];
  const accelerations = [];

  for (let i = 1; i < pointerSamples.length; i++) {
    const dx = pointerSamples[i].x - pointerSamples[i - 1].x;
    const dy = pointerSamples[i].y - pointerSamples[i - 1].y;
    const dt = Math.max(pointerSamples[i].t - pointerSamples[i - 1].t, 1);

    const velocity = Math.sqrt(dx * dx + dy * dy) / dt;
    velocities.push(velocity);

    if (i > 1) {
      const dv = velocity - velocities[i - 2];
      accelerations.push(dv / dt);
    }
  }

  if (accelerations.length === 0) {
    return { signals, evidence: { reason: 'no-acceleration-data' } };
  }

  // Fit polynomial to velocities (humans have smooth curves)
  const avgAccel = mean(accelerations);
  const vVariance = stdDev(velocities);

  const evidence = {
    sampleCount: pointerSamples.length,
    avgVelocity: round(mean(velocities), 3),
    velocityVariance: round(vVariance, 3),
    avgAcceleration: round(avgAccel, 3),
    accelerationVariance: round(stdDev(accelerations), 3)
  };

  // Bots have either very low or suspiciously constant velocity variance
  if (vVariance < 0.05 && pointerSamples.length >= 20) {
    signals.push({
      key: 'suspiciouslySmoothMouseCurve',
      label: 'Suspiciously Smooth Mouse Movement Curve',
      confidence: 66,
      severity: 'soft',
      weight: 5
    });
  }

  // Bots have near-zero acceleration (perfectly linear paths)
  if (Math.abs(avgAccel) < 0.001 && accelerations.length >= 10) {
    signals.push({
      key: 'perfectlyLinearMouseAcceleration',
      label: 'Perfectly Linear Mouse Acceleration',
      confidence: 64,
      severity: 'soft',
      weight: 5
    });
  }

  return { signals, evidence };
}

export function initializeExtendedBehaviorTracking() {
  initExtendedBehaviorTracking();
}

export function getExtendedBehaviorData() {
  return {
    formInteractions: behaviorExtendedState.formInteractions,
    scrollSessions: behaviorExtendedState.scrollSessions,
    clickNavigationPairs: behaviorExtendedState.clickNavigationPairs,
    resourceLoadTimes: behaviorExtendedState.resourceLoadTimes,
    contextSwitches: behaviorExtendedState.contextSwitches
  };
}

export function runExtendedBehaviorChecks(pointerSamples = []) {
  const signals = [];
  const evidence = {};

  // Analyze form filling
  const formAnalysis = analyzeFormFillingPatterns();
  signals.push(...formAnalysis.signals.map(s => createDetectorResult({
    key: s.key,
    label: s.label,
    value: true,
    evidence: formAnalysis.evidence,
    category: 'behavior',
    severity: s.severity,
    weight: s.weight,
    confidence: s.confidence,
    state: 'suspicious'
  })));
  evidence.formFilling = formAnalysis.evidence;

  // Analyze scroll patterns
  const scrollAnalysis = analyzeScrollPatterns();
  signals.push(...scrollAnalysis.signals.map(s => createDetectorResult({
    key: s.key,
    label: s.label,
    value: true,
    evidence: scrollAnalysis.evidence,
    category: 'behavior',
    severity: s.severity,
    weight: s.weight,
    confidence: s.confidence,
    state: 'suspicious'
  })));
  evidence.scrollPatterns = scrollAnalysis.evidence;

  // Analyze click-navigation timing
  const clickNavAnalysis = analyzeClickNavigationTiming();
  signals.push(...clickNavAnalysis.signals.map(s => createDetectorResult({
    key: s.key,
    label: s.label,
    value: true,
    evidence: clickNavAnalysis.evidence,
    category: 'behavior',
    severity: s.severity,
    weight: s.weight,
    confidence: s.confidence,
    state: 'suspicious'
  })));
  evidence.clickNavigation = clickNavAnalysis.evidence;

  // Analyze resource loading patterns
  const resourceAnalysis = analyzeResourceLoadPatterns();
  signals.push(...resourceAnalysis.signals.map(s => createDetectorResult({
    key: s.key,
    label: s.label,
    value: true,
    evidence: resourceAnalysis.evidence,
    category: 'behavior',
    severity: s.severity,
    weight: s.weight,
    confidence: s.confidence,
    state: 'suspicious'
  })));
  evidence.resourceLoading = resourceAnalysis.evidence;

  // Analyze context switching
  const contextAnalysis = analyzeContextSwitching();
  signals.push(...contextAnalysis.signals.map(s => createDetectorResult({
    key: s.key,
    label: s.label,
    value: true,
    evidence: contextAnalysis.evidence,
    category: 'behavior',
    severity: s.severity,
    weight: s.weight,
    confidence: s.confidence,
    state: 'suspicious'
  })));
  evidence.contextSwitching = contextAnalysis.evidence;

  // Analyze mouse acceleration curves
  const mouseAnalysis = analyzeMouseAccelerationCurves(pointerSamples);
  signals.push(...mouseAnalysis.signals.map(s => createDetectorResult({
    key: s.key,
    label: s.label,
    value: true,
    evidence: mouseAnalysis.evidence,
    category: 'behavior',
    severity: s.severity,
    weight: s.weight,
    confidence: s.confidence,
    state: 'suspicious'
  })));
  evidence.mouseAcceleration = mouseAnalysis.evidence;

  return { signals, evidence };
}
