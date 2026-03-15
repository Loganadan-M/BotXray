import { DETECTOR_CONFIG } from './config/detectorConfig.js';
import { createBaseResult } from './schema/resultSchema.js';
import { createRunId } from './utils/common.js';
import { createStatusController } from './ui/statusController.js';
import { renderResults } from './ui/renderResults.js';
import { computeRiskEngine } from './scoring/riskEngine.js';
import { normalizeSignals, buildSummary, computeResultChecksum, humanReadableSummary } from './reporting/resultFormatter.js';
import { runAutomationArtifactDetectors } from './detectors/automationArtifacts.js';
import { runIntegrityChecks } from './detectors/integrityChecks.js';
import { runConsistencyChecks } from './detectors/consistencyChecks.js';
import { runEnvironmentChecks } from './detectors/environmentChecks.js';
import { runFingerprintChecks } from './detectors/fingerprintChecks.js';
import { initBehaviorTracker, runBehaviorChecks } from './detectors/behaviorChecks.js';
import { runAdvancedEvasionDetection } from './detectors/advancedEvasionDetection.js';
import { runAntiDetectionDetection } from './detectors/antiDetectionDetection.js';
import { runAPISequencingChecks } from './detectors/apiSequencingChecks.js';
import { runGPURenderingEnhancements } from './detectors/gpuRenderingEnhancements.js';
import { initializeAdvancedBehaviorTracking, runAdvancedBehaviorDetection } from './detectors/advancedBehaviorTracking.js';
import { botChallenge } from './security/botChallenge.js';
import { canvasStabilityProbe, offscreenCanvasProbe } from './probes/canvasProbe.js';
import { clientRectsStabilityProbe } from './probes/clientRectsProbe.js';
import { audioStabilityProbe } from './probes/audioProbe.js';
import { getWebGLSummary } from './probes/webglProbe.js';
import { getWebRTCSummary } from './probes/webrtcProbe.js';
import { getClientHintsData } from './probes/clientHintsProbe.js';
import { getMainContextData, getWorkerContextData, getIframeContextData } from './probes/workerProbe.js';
import { textMetricsProbe } from './probes/textMetricsProbe.js';
import {
  getMediaDevicesSummary,
  getSpeechVoicesSummary,
  getConnectionSummary,
  getBatterySummary,
  getMediaCapabilitiesSummary
} from './probes/capabilitiesProbe.js';

const statusController = createStatusController();
const behaviorTracker = initBehaviorTracker();

let detectionInProgress = false;
let lastDetectionResults = null;

function gatherUnsupportedApis(probes) {
  const unsupported = [];
  Object.entries(probes).forEach(([key, value]) => {
    if (value === null || typeof value !== 'object') return;
    if (value.state === 'unavailable') unsupported.push(key);
  });
  return unsupported;
}

function gatherProbeErrors(probes) {
  const errors = [];
  Object.entries(probes).forEach(([key, value]) => {
    if (value === null || typeof value !== 'object') return;
    if (value.state === 'error') {
      errors.push({ key, error: value.error || value.reason || 'unknown-error' });
    }
  });
  return errors;
}

function analyzeInvocationStack() {
  const stack = String(new Error().stack || '');
  const lowered = stack.toLowerCase();
  const looksUserEvent = /onclick|eventlistener|htmlbuttonelement|mouseevent|pointerevent/.test(lowered);
  const looksEvalLike = /evaluate|injectedscript|<anonymous>|vm\d+|playwright|puppeteer|webdriver|cdp/.test(lowered);
  const scriptedInvocationStack = looksEvalLike && !looksUserEvent;

  return {
    scriptedInvocationStack,
    looksUserEvent,
    looksEvalLike,
    stackSample: stack.split('\n').slice(0, 5).join('\n')
  };
}

async function collectProbes() {
  const webglSummary = DETECTOR_CONFIG.enabledDetectors.probes.webgl ? getWebGLSummary() : { state: 'unavailable' };
  const canvasProbe = DETECTOR_CONFIG.enabledDetectors.probes.canvas ? canvasStabilityProbe() : { state: 'unavailable' };
  const rectProbe = DETECTOR_CONFIG.enabledDetectors.probes.clientRects ? clientRectsStabilityProbe() : { state: 'unavailable' };
  const textProbe = DETECTOR_CONFIG.enabledDetectors.probes.textMetrics ? textMetricsProbe() : { state: 'unavailable' };
  const mainContext = getMainContextData();
  const speechVoices = DETECTOR_CONFIG.enabledDetectors.probes.speechVoices ? getSpeechVoicesSummary() : { state: 'unavailable' };
  const connectionSummary = DETECTOR_CONFIG.enabledDetectors.probes.connection ? getConnectionSummary() : { state: 'unavailable' };
  const mediaCapabilitiesSummary = DETECTOR_CONFIG.enabledDetectors.probes.mediaCapabilities
    ? getMediaCapabilitiesSummary()
    : { state: 'unavailable' };

  const [
    webrtcSummary,
    clientHints,
    workerContext,
    iframeContext,
    audioProbe,
    offscreenProbe,
    mediaDevicesSummary,
    batterySummary
  ] = await Promise.all([
    DETECTOR_CONFIG.enabledDetectors.probes.webrtc ? getWebRTCSummary(DETECTOR_CONFIG.probeTimeouts.webrtcMs) : Promise.resolve({ state: 'unavailable' }),
    getClientHintsData(),
    DETECTOR_CONFIG.enabledDetectors.probes.worker ? getWorkerContextData(DETECTOR_CONFIG.probeTimeouts.workerMs) : Promise.resolve({ state: 'unavailable' }),
    getIframeContextData(),
    DETECTOR_CONFIG.enabledDetectors.probes.audio ? audioStabilityProbe() : Promise.resolve({ state: 'unavailable' }),
    DETECTOR_CONFIG.enabledDetectors.probes.offscreenCanvas ? offscreenCanvasProbe() : Promise.resolve({ state: 'unavailable' }),
    DETECTOR_CONFIG.enabledDetectors.probes.mediaDevices ? getMediaDevicesSummary() : Promise.resolve({ state: 'unavailable' }),
    DETECTOR_CONFIG.enabledDetectors.probes.batterySummary ? getBatterySummary() : Promise.resolve({ state: 'unavailable' })
  ]);

  return {
    webglSummary,
    canvasProbe,
    rectProbe,
    textProbe,
    webrtcSummary,
    clientHints,
    workerContext,
    iframeContext,
    audioProbe,
    offscreenProbe,
    mainContext,
    mediaDevicesSummary,
    speechVoices,
    connectionSummary,
    batterySummary,
    mediaCapabilitiesSummary
  };
}

async function detectBot({ runContext } = {}) {
  const startedAt = performance.now();
  const ua = navigator.userAgent || '';
  const probes = await collectProbes();

  const automationResult = DETECTOR_CONFIG.enabledDetectors.automationArtifacts
    ? runAutomationArtifactDetectors({
      ua,
      iframeContext: probes.iframeContext,
      workerContext: probes.workerContext,
      webglSummary: probes.webglSummary,
      canvasProbe: probes.canvasProbe,
      offscreenProbe: probes.offscreenProbe
    })
    : { signals: [], evidence: {} };

  const integrityResult = DETECTOR_CONFIG.enabledDetectors.integrityChecks
    ? runIntegrityChecks()
    : { signals: [], weakChecks: [], evidence: {} };

  const consistencyResult = DETECTOR_CONFIG.enabledDetectors.consistencyChecks
    ? await runConsistencyChecks({
      ua,
      clientHints: probes.clientHints,
      mainContext: probes.mainContext,
      workerContext: probes.workerContext,
      iframeContext: probes.iframeContext,
      webglSummary: probes.webglSummary
    })
    : { signals: [], weakChecks: [], evidence: {} };

  const environmentResult = DETECTOR_CONFIG.enabledDetectors.environmentChecks
    ? runEnvironmentChecks({
      ua,
      webglSummary: probes.webglSummary,
      webrtcSummary: probes.webrtcSummary,
      mediaCapabilitiesSummary: probes.mediaCapabilitiesSummary
    })
    : { signals: [], evidence: {} };

  const fingerprintResult = runFingerprintChecks({
    canvasProbe: probes.canvasProbe,
    offscreenProbe: probes.offscreenProbe,
    rectProbe: probes.rectProbe,
    audioProbe: probes.audioProbe,
    textProbe: probes.textProbe
  });

  const behaviorResult = DETECTOR_CONFIG.enabledDetectors.behaviorChecks
    ? runBehaviorChecks({
      trackerState: behaviorTracker.state,
      behaviorConfig: DETECTOR_CONFIG.behavior,
      runContext
    })
    : { signals: [], telemetry: {} };

  let advancedEvasionResult = { signals: [] };
  if (DETECTOR_CONFIG.enabledDetectors.advancedEvasionDetection) {
    try {
      advancedEvasionResult = runAdvancedEvasionDetection() || { signals: [] };
    } catch (e) {
      console.warn('[Detection] Advanced evasion detection failed:', e.message);
    }
  }

  let antiDetectionResult = { signals: [] };
  if (DETECTOR_CONFIG.enabledDetectors.antiDetectionDetection) {
    try {
      antiDetectionResult = runAntiDetectionDetection() || { signals: [] };
    } catch (e) {
      console.warn('[Detection] Anti-detection detection failed:', e.message);
    }
  }

  let apiSequencingResult = { signals: [] };
  if (DETECTOR_CONFIG.enabledDetectors.apiSequencingChecks) {
    try {
      apiSequencingResult = runAPISequencingChecks() || { signals: [] };
    } catch (e) {
      console.warn('[Detection] API sequencing checks failed:', e.message);
    }
  }

  let gpuRenderingResult = { signals: [] };
  if (DETECTOR_CONFIG.enabledDetectors.gpuRenderingEnhancements) {
    try {
      gpuRenderingResult = runGPURenderingEnhancements() || { signals: [] };
    } catch (e) {
      console.warn('[Detection] GPU rendering enhancements failed:', e.message);
    }
  }

  let advancedBehaviorResult = { signals: [] };
  if (DETECTOR_CONFIG.enabledDetectors.behaviorChecks) {
    try {
      advancedBehaviorResult = runAdvancedBehaviorDetection() || { signals: [] };
      console.log('[Detection] Advanced behavior analysis:', advancedBehaviorResult.signals.length, 'signals');
    } catch (e) {
      console.warn('[Detection] Advanced behavior detection failed:', e.message);
    }
  }

  const signals = [
    ...automationResult.signals,
    ...integrityResult.signals,
    ...consistencyResult.signals,
    ...fingerprintResult.signals,
    ...environmentResult.signals,
    ...behaviorResult.signals,
    ...(advancedEvasionResult.signals || []),
    ...(antiDetectionResult.signals || []),
    ...(apiSequencingResult.signals || []),
    ...(gpuRenderingResult.signals || []),
    ...(advancedBehaviorResult.signals || [])
  ];

  const weakChecks = [
    ...(integrityResult.weakChecks || []),
    ...(consistencyResult.weakChecks || [])
  ];

  const scoring = computeRiskEngine({
    signals,
    weakChecks,
    config: DETECTOR_CONFIG
  });

  const base = createBaseResult({
    detectorVersion: DETECTOR_CONFIG.detectorVersion,
    runId: createRunId()
  });

  const normalizedSignals = normalizeSignals(signals);

  const runtimeInfo = {
    criticalHits: scoring.criticalHits,
    consistencyRewardApplied: scoring.consistencyRewardApplied,
    consistentChecks: scoring.consistentChecks,
    consistencyRewardSkippedReason: scoring.consistencyRewardSkippedReason
  };

  const summary = buildSummary({
    signals: normalizedSignals,
    weakChecks,
    probes,
    telemetry: behaviorResult.telemetry,
    runtimeInfo
  });

  const result = {
    ...base,
    version: DETECTOR_CONFIG.detectorVersion,
    elapsedMs: Math.round(performance.now() - startedAt),
    score100: scoring.score100,
    botScore: scoring.botScore,
    riskLabel: scoring.riskLabel,
    action: scoring.action,
    confidence: scoring.confidence,
    categoryBreakdown: scoring.categoryBreakdown,
    signals: normalizedSignals,
    strongSignals: normalizedSignals,
    weakChecks,
    explanations: scoring.explanations,
    summary,
    integrity: {
      configFrozen: Object.isFrozen(DETECTOR_CONFIG),
      runtime: {
        unsupportedApis: gatherUnsupportedApis(probes),
        errors: gatherProbeErrors(probes)
      }
    }
  };

  result.checksum = computeResultChecksum(result);
  result.humanSummary = humanReadableSummary(result);

  // Trigger challenge if risk score is high
  if (typeof window !== 'undefined' && result.score100 >= 60) {
    console.log('[Detection] High risk score detected. Considering challenge...');
    // Challenge will be shown by the UI, not here
  }

  return result;
}

function buildRunContext(options = {}) {
  const activation = navigator.userActivation || {};
  const explicitTrigger = options?.triggerType || options?.trigger;
  const fallbackTrigger = activation.isActive ? 'user-active' : 'programmatic';
  const invocation = analyzeInvocationStack();
  return {
    triggerType: explicitTrigger || fallbackTrigger,
    userActivation: {
      isActive: !!activation.isActive,
      hasBeenActive: !!activation.hasBeenActive
    },
    visibilityState: document.visibilityState || 'unknown',
    hasFocus: typeof document.hasFocus === 'function' ? document.hasFocus() : null,
    scriptedInvocationStack: invocation.scriptedInvocationStack,
    invocationMeta: invocation
  };
}

async function runDetection(options = {}) {
  if (detectionInProgress) {
    console.warn('[Detection] Already in progress');
    return lastDetectionResults;
  }

  detectionInProgress = true;
  statusController.setLoading(true);
  const output = document.getElementById('jsonOutput');
  if (output) output.textContent = 'Analyzing browser signals, please wait...';

  try {
    console.log('[Detection] Starting bot detection...');
    const runContext = buildRunContext(options);
    console.log('[Detection] Run context:', runContext);

    const result = await detectBot({ runContext });
    console.log('[Detection] Results received:', result);

    lastDetectionResults = result;
    renderResults(result);

    console.log('[Detection] Completed. Score:', result.botScore, 'Risk:', result.riskLabel);

    return result;
  } catch (error) {
    const errorText = error && error.message ? error.message : String(error);
    console.error('[Detection] FAILED:', errorText);
    console.error('[Detection Details]:', error);
    if (output) output.textContent = `Detection failed: ${errorText}`;
    return null;
  } finally {
    statusController.setLoading(false);
    detectionInProgress = false;
  }
}

window.runDetection = runDetection;

// Expose bot challenge system to window
window.botChallenge = botChallenge;

function bootstrap() {
  if (window.speechSynthesis && typeof window.speechSynthesis.getVoices === 'function') {
    window.speechSynthesis.getVoices();
  }

  // Initialize advanced behavior tracking
  try {
    initializeAdvancedBehaviorTracking();
    console.log('[Detection] Advanced behavior tracking initialized');
  } catch (e) {
    console.warn('[Detection] Failed to initialize behavior tracking:', e.message);
  }

  if (DETECTOR_CONFIG.autoRun) {
    setTimeout(() => {
      runDetection({ triggerType: 'auto' });
    }, DETECTOR_CONFIG.autoRunDelayMs);
  }
}

window.addEventListener('load', bootstrap);
