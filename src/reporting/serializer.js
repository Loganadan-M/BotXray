export function serializeDetectionResult(payload) {
  return JSON.stringify(payload);
}

export function toBackendPayload(payload) {
  return {
    schemaVersion: payload.schemaVersion,
    detectorVersion: payload.detectorVersion,
    runId: payload.runId,
    timestamp: payload.timestamp,
    score100: payload.score100,
    botScore: payload.botScore,
    riskLabel: payload.riskLabel,
    action: payload.action,
    confidence: payload.confidence,
    categoryBreakdown: payload.categoryBreakdown,
    summary: payload.summary,
    explanations: payload.explanations,
    signals: payload.signals,
    weakChecks: payload.weakChecks,
    integrity: payload.integrity,
    checksum: payload.checksum
  };
}
