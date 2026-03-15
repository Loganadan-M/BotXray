import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';
import { suspiciousFontProfile } from '../probes/textMetricsProbe.js';

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

export function runFingerprintChecks({ canvasProbe, offscreenProbe, rectProbe, audioProbe, textProbe }) {
  const offscreenSuspicious = offscreenProbe?.state === 'ok' && (
    !offscreenProbe.stable || !offscreenProbe.hash
  );

  const signals = [
    buildSignal('canvasOutputUnstable', 'Canvas output unstable across repeated calls', canvasProbe?.state === 'ok' && !canvasProbe.stable, canvasProbe, canvasProbe?.state || STATES.UNAVAILABLE),
    buildSignal('offscreenCanvasMismatch', 'OffscreenCanvas output unstable or malformed', !!offscreenSuspicious, {
      mainHash: canvasProbe?.hash || null,
      offscreenHash: offscreenProbe?.hash || null,
      offscreenStable: offscreenProbe?.stable ?? null,
      offscreenState: offscreenProbe?.state || 'unavailable'
    }, offscreenProbe?.state || STATES.UNAVAILABLE),
    buildSignal('clientRectsUnstable', 'Client rects unstable across repeated reads', rectProbe?.state === 'ok' && !rectProbe.stable, rectProbe, rectProbe?.state || STATES.UNAVAILABLE),
    buildSignal('audioOutputUnstable', 'Audio fingerprint unstable across repeated renders', audioProbe?.state === 'ok' && !audioProbe.stable, audioProbe, audioProbe?.state || STATES.UNAVAILABLE),
    buildSignal('textMetricsUnstable', 'Text metrics unstable across repeated measures', textProbe?.state === 'ok' && !textProbe.stable, textProbe, textProbe?.state || STATES.UNAVAILABLE),
    buildSignal('suspiciousFontProfile', 'Text metrics show unusually low font differentiation', textProbe?.state === 'ok' && suspiciousFontProfile(textProbe), {
      fontPresence: textProbe?.fontPresence,
      hash: textProbe?.hash
    }, textProbe?.state || STATES.UNAVAILABLE)
  ];

  return {
    signals,
    evidence: {
      canvasProbe,
      offscreenProbe,
      rectProbe,
      audioProbe,
      textProbe
    }
  };
}
