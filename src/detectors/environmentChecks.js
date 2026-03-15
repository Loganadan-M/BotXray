import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';
import { uaIsChromiumFamily } from './automationArtifacts.js';

function isSuspiciousDeviceMemory() {
  const value = navigator.deviceMemory;
  if (typeof value !== 'number' || !Number.isFinite(value)) return false;
  if (value < 0.25 || value > 64) return true;
  const plausible = [0.25, 0.5, 1, 2, 4, 8, 16, 32, 64];
  return !plausible.includes(value);
}

function isSuspiciousHardwareConcurrency() {
  const value = navigator.hardwareConcurrency;
  if (typeof value !== 'number' || !Number.isFinite(value)) return true;
  return value < 1 || value > 128;
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

function mediaCapabilitiesMismatch({ ua, mediaCapabilitiesSummary }) {
  if (mediaCapabilitiesSummary?.state !== 'ok') return { suspicious: false, state: STATES.UNAVAILABLE, details: mediaCapabilitiesSummary };
  const chromium = uaIsChromiumFamily(ua);
  if (!chromium) return { suspicious: false, state: STATES.OK, details: mediaCapabilitiesSummary };

  const suspicious = !mediaCapabilitiesSummary.hasDecodingInfo;
  return {
    suspicious,
    state: STATES.OK,
    details: mediaCapabilitiesSummary
  };
}

export function runEnvironmentChecks({ ua, webglSummary, webrtcSummary, mediaCapabilitiesSummary }) {
  const suspiciousDeviceMemory = isSuspiciousDeviceMemory();
  const suspiciousHardwareConcurrency = isSuspiciousHardwareConcurrency();
  const webglRenderer = webglSummary?.renderer || '';
  const swiftShaderOrNoWebGL = !webglRenderer || /SwiftShader|llvmpipe/i.test(webglRenderer);
  const zeroPluginsChromium = uaIsChromiumFamily(ua) && navigator.plugins && navigator.plugins.length === 0;
  const mediaMismatch = mediaCapabilitiesMismatch({ ua, mediaCapabilitiesSummary });

  const signals = [
    buildSignal('suspiciousDeviceMemory', 'navigator.deviceMemory out of plausible range', suspiciousDeviceMemory, navigator.deviceMemory),
    buildSignal('suspiciousHardwareConcurrency', 'navigator.hardwareConcurrency out of plausible range', suspiciousHardwareConcurrency, navigator.hardwareConcurrency),
    buildSignal('swiftShaderOrNoWebGL', 'SwiftShader/software/no WebGL renderer', swiftShaderOrNoWebGL, webglSummary, webglSummary?.state === 'ok' ? STATES.OK : STATES.UNAVAILABLE),
    buildSignal('zeroPluginsChromium', 'Chromium with zero plugins', zeroPluginsChromium, navigator.plugins ? navigator.plugins.length : null),
    buildSignal(
      'webrtcNoHostCandidate',
      'WebRTC has no host candidate',
      webrtcSummary?.state === 'ok' && webrtcSummary.supported && !webrtcSummary.hasHostCandidate,
      webrtcSummary,
      webrtcSummary?.state === 'ok' ? STATES.OK : STATES.UNAVAILABLE
    ),
    buildSignal('mediaCapabilitiesMismatch', 'Media capabilities mismatch for browser family', mediaMismatch.suspicious, mediaMismatch.details, mediaMismatch.state)
  ];

  return {
    signals,
    evidence: {
      suspiciousDeviceMemory,
      suspiciousHardwareConcurrency,
      webglSummary,
      webrtcSummary,
      mediaCapabilitiesSummary
    }
  };
}
