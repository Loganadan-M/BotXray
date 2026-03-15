/**
 * Enhanced Timeout and Fallback Handling
 * Improves probe reliability with better timeout strategies and suspicious handling
 */

import { createDetectorResult, STATES } from '../schema/detectorTypes.js';

export class ProbeExecutor {
  constructor(timeoutMs = 5000) {
    this.timeoutMs = timeoutMs;
    this.probeTimings = [];
    this.timeoutEvents = [];
  }

  /**
   * Execute a probe with timeout and fallback handling
   */
  async executeWithTimeout(probeFunction, probeName, options = {}) {
    const {
      timeoutMs = this.timeoutMs,
      treatTimeoutAsSuspicious = false,
      fallbackValue = null,
      criticalProbe = false
    } = options;

    const startTime = performance.now();

    return Promise.race([
      probeFunction(),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error(`${probeName} timeout after ${timeoutMs}ms`)),
          timeoutMs
        )
      )
    ]).then(
      result => {
        const elapsedMs = performance.now() - startTime;
        this.probeTimings.push({
          probe: probeName,
          elapsedMs,
          success: true,
          timeout: false
        });

        return {
          state: 'ok',
          data: result,
          elapsedMs,
          probeStatus: 'completed'
        };
      },
      error => {
        const elapsedMs = performance.now() - startTime;
        const isTimeout = elapsedMs >= timeoutMs - 10;

        this.timeoutEvents.push({
          probe: probeName,
          elapsedMs,
          error: String(error),
          timeout: isTimeout,
          critical: criticalProbe
        });

        this.probeTimings.push({
          probe: probeName,
          elapsedMs,
          success: false,
          timeout: isTimeout
        });

        // Determine handling strategy
        if (isTimeout) {
          // Timeouts can indicate:
          // 1. Genuine browser performance issues
          // 2. Headless browser constraints (WebRTC, worker context)
          // 3. Bot detection circumvention (deliberate timeout)

          if (treatTimeoutAsSuspicious || criticalProbe) {
            return {
              state: 'suspicious',
              reason: `${probeName} timeout (${elapsedMs}ms)`,
              elapsedMs,
              probeStatus: 'timeout',
              suspicionConfidence: 0.62
            };
          } else {
            return {
              state: 'unavailable',
              reason: `${probeName} timeout`,
              elapsedMs,
              probeStatus: 'timeout',
              fallback: fallbackValue
            };
          }
        } else {
          // Non-timeout errors
          return {
            state: 'error',
            reason: String(error),
            elapsedMs,
            probeStatus: 'error',
            fallback: fallbackValue
          };
        }
      }
    );
  }

  /**
   * Execute multiple probes in parallel with timeout management
   */
  async executeParallel(probes, options = {}) {
    const {
      treatTimeoutAsSuspicious = false,
      timeoutMs = this.timeoutMs
    } = options;

    const results = {};

    const probePromises = Object.entries(probes).map(([name, fn]) =>
      this.executeWithTimeout(fn, name, {
        timeoutMs,
        treatTimeoutAsSuspicious,
        ...options[name]
      }).then(result => {
        results[name] = result;
      })
    );

    await Promise.all(probePromises);

    return results;
  }

  /**
   * Analyze timeout patterns for bot detection
   */
  analyzeTimeoutPatterns() {
    const analysis = {
      totalProbes: this.probeTimings.length,
      successfulProbes: this.probeTimings.filter(p => p.success).length,
      timeoutProbes: this.probeTimings.filter(p => p.timeout).length,
      failureProbes: this.probeTimings.filter(p => !p.success).length,
      avgElapsedMs: 0,
      suspiciousPatterns: []
    };

    if (this.probeTimings.length === 0) {
      return analysis;
    }

    // Calculate averages
    const successfulTimings = this.probeTimings.filter(p => p.success).map(p => p.elapsedMs);
    if (successfulTimings.length > 0) {
      analysis.avgElapsedMs = successfulTimings.reduce((a, b) => a + b, 0) / successfulTimings.length;
    }

    // Detect suspicious patterns
    const timeoutRate = analysis.timeoutProbes / analysis.totalProbes;

    // High timeout rate suggests headless or detection circumvention
    if (timeoutRate > 0.3) {
      analysis.suspiciousPatterns.push({
        type: 'high-timeout-rate',
        rate: timeoutRate,
        confidence: 0.65
      });
    }

    // Specific probes consistently timing out (headless browser indicators)
    const timedOutProbes = this.timeoutEvents.map(t => t.probe);
    const uniqueTimeouts = new Set(timedOutProbes);

    if (timedOutProbes.includes('webrtc') && timedOutProbes.includes('worker')) {
      analysis.suspiciousPatterns.push({
        type: 'concurrent-timeout-cluster',
        probes: ['webrtc', 'worker'],
        confidence: 0.70
      });
    }

    // Check for critical probes timing out
    const criticalTimeouts = this.timeoutEvents.filter(t => t.critical);
    if (criticalTimeouts.length > 0) {
      analysis.suspiciousPatterns.push({
        type: 'critical-probe-timeout',
        count: criticalTimeouts.length,
        confidence: 0.72
      });
    }

    // Suspiciously fast completions (all probes complete in <100ms)
    if (analysis.avgElapsedMs > 0 && analysis.avgElapsedMs < 100 && analysis.successfulProbes > 5) {
      analysis.suspiciousPatterns.push({
        type: 'suspiciously-fast-probe-execution',
        avgElapsed: analysis.avgElapsedMs,
        confidence: 0.60
      });
    }

    return analysis;
  }

  /**
   * Get probe execution statistics
   */
  getStatistics() {
    return {
      probeCount: this.probeTimings.length,
      timeoutCount: this.timeoutEvents.length,
      totalElapsedMs: this.probeTimings.reduce((a, p) => a + p.elapsedMs, 0),
      avgElapsedMs: this.probeTimings.length > 0
        ? this.probeTimings.reduce((a, p) => a + p.elapsedMs, 0) / this.probeTimings.length
        : 0,
      timeouts: this.timeoutEvents.map(t => ({
        probe: t.probe,
        elapsedMs: t.elapsedMs,
        critical: t.critical
      }))
    };
  }
}

/**
 * Convert timeout patterns to detection signals
 */
export function createTimeoutSignals(timeoutAnalysis) {
  const signals = [];

  timeoutAnalysis.suspiciousPatterns.forEach(pattern => {
    switch (pattern.type) {
      case 'high-timeout-rate':
        signals.push(
          createDetectorResult({
            key: 'probeTim outRateHigh',
            label: 'High Probe Timeout Rate',
            value: true,
            evidence: pattern,
            category: 'environment',
            severity: 'soft',
            weight: 4,
            confidence: Math.round(pattern.confidence * 100),
            state: 'suspicious'
          })
        );
        break;

      case 'concurrent-timeout-cluster':
        signals.push(
          createDetectorResult({
            key: 'concurrentProbeTimeouts',
            label: 'Concurrent Probe Timeout Cluster',
            value: true,
            evidence: pattern,
            category: 'environment',
            severity: 'hard',
            weight: 6,
            confidence: Math.round(pattern.confidence * 100),
            state: 'suspicious'
          })
        );
        break;

      case 'critical-probe-timeout':
        signals.push(
          createDetectorResult({
            key: 'criticalProbeTimeout',
            label: 'Critical Probe Timeout',
            value: true,
            evidence: pattern,
            category: 'environment',
            severity: 'hard',
            weight: 7,
            confidence: Math.round(pattern.confidence * 100),
            state: 'suspicious'
          })
        );
        break;

      case 'suspiciously-fast-probe-execution':
        signals.push(
          createDetectorResult({
            key: 'suspiciouslyFastProbes',
            label: 'Suspiciously Fast Probe Execution',
            value: true,
            evidence: pattern,
            category: 'environment',
            severity: 'soft',
            weight: 4,
            confidence: Math.round(pattern.confidence * 100),
            state: 'suspicious'
          })
        );
        break;
    }
  });

  return signals;
}

/**
 * Export probe executor singleton with reasonable defaults
 */
export const globalProbeExecutor = new ProbeExecutor(5000);
