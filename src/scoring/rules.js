import { deepFreeze } from '../utils/common.js';
import { SEVERITIES } from '../schema/detectorTypes.js';

const rules = {
  webdriverTrue: { weight: 14, confidence: 98, category: 'automation', severity: SEVERITIES.HARD },
  iframeWebdriverTrue: { weight: 10, confidence: 95, category: 'automation', severity: SEVERITIES.HARD },
  workerWebdriverTrue: { weight: 10, confidence: 95, category: 'automation', severity: SEVERITIES.HARD },
  playwrightArtifacts: { weight: 11, confidence: 96, category: 'automation', severity: SEVERITIES.HARD },
  seleniumArtifacts: { weight: 11, confidence: 96, category: 'automation', severity: SEVERITIES.HARD },
  domAutomationGlobals: { weight: 11, confidence: 96, category: 'automation', severity: SEVERITIES.HARD },
  phantomOrNightmare: { weight: 8, confidence: 92, category: 'automation', severity: SEVERITIES.HARD },
  headlessTokenInUA: { weight: 10, confidence: 90, category: 'automation', severity: SEVERITIES.HARD },
  headlessAutomationCluster: { weight: 12, confidence: 95, category: 'automation', severity: SEVERITIES.HARD },
  gologinKeywordArtifacts: { weight: 9, confidence: 92, category: 'automation', severity: SEVERITIES.HARD },
  cdpStackHook: { weight: 7, confidence: 84, category: 'automation', severity: SEVERITIES.HARD },
  suspiciousWindowGlobals: { weight: 6, confidence: 78, category: 'automation', severity: SEVERITIES.SOFT },

  patchedFingerprintGetters: { weight: 9, confidence: 87, category: 'integrity', severity: SEVERITIES.HARD },
  patchedNavigatorPrototype: { weight: 9, confidence: 87, category: 'integrity', severity: SEVERITIES.HARD },
  permissionsQueryPatched: { weight: 4, confidence: 65, category: 'integrity', severity: SEVERITIES.SOFT },
  functionToStringTamper: { weight: 5, confidence: 74, category: 'integrity', severity: SEVERITIES.SOFT },

  workerMismatch: { weight: 7, confidence: 78, category: 'consistency', severity: SEVERITIES.SOFT },
  platformMismatch: { weight: 7, confidence: 80, category: 'consistency', severity: SEVERITIES.SOFT },
  clientHintsMismatch: { weight: 6, confidence: 76, category: 'consistency', severity: SEVERITIES.SOFT },
  webglPlatformMismatch: { weight: 5, confidence: 70, category: 'consistency', severity: SEVERITIES.SOFT },
  languageInconsistent: { weight: 4, confidence: 65, category: 'consistency', severity: SEVERITIES.SOFT },
  timezoneLocaleMismatch: { weight: 4, confidence: 65, category: 'consistency', severity: SEVERITIES.SOFT },
  notificationPermissionMismatch: { weight: 4, confidence: 66, category: 'consistency', severity: SEVERITIES.SOFT },
  pluginMimeInconsistent: { weight: 5, confidence: 75, category: 'consistency', severity: SEVERITIES.SOFT },
  screenGeometryInconsistent: { weight: 5, confidence: 73, category: 'consistency', severity: SEVERITIES.SOFT },
  touchUaInconsistent: { weight: 4, confidence: 69, category: 'consistency', severity: SEVERITIES.SOFT },
  chromeObjectInconsistent: { weight: 6, confidence: 78, category: 'consistency', severity: SEVERITIES.SOFT },
  devicePixelRatioImplausible: { weight: 4, confidence: 64, category: 'consistency', severity: SEVERITIES.SOFT },
  mobileDesktopTraitMismatch: { weight: 5, confidence: 70, category: 'consistency', severity: SEVERITIES.SOFT },

  canvasOutputUnstable: { weight: 8, confidence: 80, category: 'fingerprint', severity: SEVERITIES.HARD },
  offscreenCanvasMismatch: { weight: 5, confidence: 70, category: 'fingerprint', severity: SEVERITIES.SOFT },
  clientRectsUnstable: { weight: 7, confidence: 77, category: 'fingerprint', severity: SEVERITIES.SOFT },
  audioOutputUnstable: { weight: 7, confidence: 77, category: 'fingerprint', severity: SEVERITIES.SOFT },
  swiftShaderOrNoWebGL: { weight: 4, confidence: 58, category: 'fingerprint', severity: SEVERITIES.SOFT },
  textMetricsUnstable: { weight: 5, confidence: 68, category: 'fingerprint', severity: SEVERITIES.SOFT },
  suspiciousFontProfile: { weight: 3, confidence: 55, category: 'fingerprint', severity: SEVERITIES.SOFT },

  suspiciousDeviceMemory: { weight: 5, confidence: 72, category: 'environment', severity: SEVERITIES.SOFT },
  suspiciousHardwareConcurrency: { weight: 4, confidence: 72, category: 'environment', severity: SEVERITIES.SOFT },
  zeroPluginsChromium: { weight: 3, confidence: 45, category: 'environment', severity: SEVERITIES.SOFT },
  webrtcNoHostCandidate: { weight: 3, confidence: 42, category: 'environment', severity: SEVERITIES.SOFT },
  mediaCapabilitiesMismatch: { weight: 4, confidence: 60, category: 'environment', severity: SEVERITIES.SOFT },

  noHumanInteraction: { weight: 2, confidence: 40, category: 'behavior', severity: SEVERITIES.SOFT },
  lowInteractionEntropy: { weight: 3, confidence: 52, category: 'behavior', severity: SEVERITIES.SOFT },
  suspiciousMousePattern: { weight: 4, confidence: 60, category: 'behavior', severity: SEVERITIES.SOFT },
  suspiciousClickCadence: { weight: 3, confidence: 58, category: 'behavior', severity: SEVERITIES.SOFT },
  suspiciousScrollBurst: { weight: 2, confidence: 45, category: 'behavior', severity: SEVERITIES.SOFT },
  programmaticNoActivation: { weight: 9, confidence: 88, category: 'behavior', severity: SEVERITIES.HARD },
  scriptedInvocationStack: { weight: 8, confidence: 84, category: 'behavior', severity: SEVERITIES.HARD }
};

export const DETECTOR_RULES = deepFreeze(rules);

export function resolveRule(key) {
  return DETECTOR_RULES[key] || {
    weight: 1,
    confidence: 50,
    category: 'consistency',
    severity: SEVERITIES.SOFT
  };
}
