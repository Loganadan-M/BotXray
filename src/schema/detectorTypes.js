/**
 * @typedef {'automation'|'fingerprint'|'consistency'|'behavior'|'environment'|'integrity'} DetectorCategory
 * @typedef {'hard'|'soft'} DetectorSeverity
 * @typedef {'ok'|'suspicious'|'unavailable'|'error'} DetectorState
 */

export const CATEGORIES = Object.freeze([
  'automation',
  'fingerprint',
  'consistency',
  'behavior',
  'environment',
  'integrity'
]);

export const STATES = Object.freeze({
  OK: 'ok',
  SUSPICIOUS: 'suspicious',
  UNAVAILABLE: 'unavailable',
  ERROR: 'error'
});

export const SEVERITIES = Object.freeze({
  HARD: 'hard',
  SOFT: 'soft'
});

export function createDetectorResult({
  key,
  label,
  value = false,
  severity = SEVERITIES.SOFT,
  weight = 1,
  confidence = 50,
  evidence = null,
  category = 'consistency',
  state = STATES.OK,
  tags = []
}) {
  return {
    key,
    label,
    value: !!value,
    severity,
    weight,
    confidence,
    evidence,
    category,
    state,
    tags
  };
}

export function createWeakCheck({ key, label, ok, details = null, category = 'consistency', state }) {
  return {
    key,
    label,
    ok: !!ok,
    details,
    category,
    state: state || (ok ? STATES.OK : STATES.SUSPICIOUS)
  };
}
