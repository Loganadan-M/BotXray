import { nowIso } from '../utils/common.js';

export const RESULT_SCHEMA_VERSION = '1.0.0';

export function createBaseResult({ detectorVersion, runId }) {
  return {
    schemaVersion: RESULT_SCHEMA_VERSION,
    detectorVersion,
    runId,
    timestamp: nowIso(),
    elapsedMs: 0,
    score100: 0,
    botScore: 0,
    riskLabel: 'LOW',
    action: 'ALLOW',
    confidence: 0,
    categoryBreakdown: {
      automation: 0,
      fingerprint: 0,
      consistency: 0,
      behavior: 0,
      environment: 0,
      integrity: 0
    },
    signals: [],
    weakChecks: [],
    summary: {},
    explanations: [],
    integrity: {
      configFrozen: false,
      runtime: {
        unsupportedApis: [],
        errors: []
      }
    }
  };
}
