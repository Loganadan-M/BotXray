import { deepFreeze } from '../utils/common.js';

const rawConfig = {
  detectorVersion: '4.0.0',
  autoRun: false,
  autoRunDelayMs: 900,
  debug: false,
  probeTimeouts: {
    webrtcMs: 2600,
    workerMs: 1400,
    audioMs: 2500
  },
  behavior: {
    suspiciousNoInteractionMs: 1500,
    programmaticNoActivationMinDwellMs: 0,
    minimumEntropyEvents: 4,
    straightLineRatioThreshold: 0.95,
    lowVelocityThreshold: 0.01,
    highBurstinessThreshold: 0.9,
    maxIdleGapMs: 12000
  },
  scoring: {
    categoryWeights: {
      automation: 1.2,
      fingerprint: 1,
      consistency: 0.9,
      behavior: 0.75,
      environment: 0.8,
      integrity: 1.1
    },
    criticalSignalKeys: [
      'webdriverTrue',
      'iframeWebdriverTrue',
      'workerWebdriverTrue',
      'playwrightArtifacts',
      'seleniumArtifacts',
      'domAutomationGlobals',
      'headlessAutomationCluster',
      'gologinKeywordArtifacts',
      'phantomOrNightmare',
      'patchedNavigatorPrototype',
      'cdpStackHook',
      'scriptedInvocationStack',
      'advancedProxyPatching',
      'performanceNowSpoofing',
      'undetectedChromedriverPatterns',
      'multiSessionEvasionPattern',
      'detectionCircumventionAttempt',
      'fetchXhrIntercepted',
      'errorStackManipulation',
      'consoleIntercepted'
    ],
    criticalEscalationFloors: [
      { minCriticalHits: 3, minScore: 80 },
      { minCriticalHits: 2, minScore: 64 },
      { minCriticalHits: 1, minScore: 42 }
    ],
    clusterEscalationRules: [
      {
        key: 'scriptedNoActivationGraphicsCluster',
        requireAllKeys: ['canvasOutputUnstable', 'offscreenCanvasMismatch'],
        requireAnyKeys: ['programmaticNoActivation', 'scriptedInvocationStack'],
        minScore: 36
      }
    ],
    consistencyReward: {
      minConsistentChecks: 8,
      scoreReduction: 8,
      maxSuspiciousSignals: 3,
      maxHardSuspiciousSignals: 0,
      skipWhenCriticalHits: true
    },
    actionMapping: [
      { minScore: 80, riskLabel: 'CRITICAL', action: 'BLOCK' },
      { minScore: 60, riskLabel: 'HIGH', action: 'CHALLENGE' },
      { minScore: 30, riskLabel: 'MEDIUM', action: 'MONITOR' },
      { minScore: 0, riskLabel: 'LOW', action: 'ALLOW' }
    ]
  },
  enabledDetectors: {
    automationArtifacts: true,
    consistencyChecks: true,
    environmentChecks: true,
    behaviorChecks: true,
    integrityChecks: true,
    // New Advanced Detectors (v4.0)
    advancedEvasionDetection: true,
    extendedBehaviorAnalysis: true,
    networkIntelligence: true,
    gpuRenderingEnhancements: true,
    apiSequencingChecks: true,
    enhancedConsistencyChecks: true,
    multiSessionCorrelation: true,
    antiDetectionDetection: true,
    probes: {
      canvas: true,
      offscreenCanvas: true,
      clientRects: true,
      audio: true,
      textMetrics: true,
      webgl: true,
      webrtc: true,
      worker: true,
      mediaDevices: true,
      mediaCapabilities: true,
      speechVoices: true,
      connection: true,
      batterySummary: true
    }
  },
  unavailablePolicy: {
    treatUnavailableAsSuspicious: false,
    unavailablePenaltyWeight: 0.2
  },
  scoreToBotScoreDivisor: 4,
  maxBotScore: 25
};

export const DETECTOR_CONFIG = deepFreeze(rawConfig);
