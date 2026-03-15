/**
 * Multi-Session Correlation Module
 * Tracks detection attempts across sessions and correlates patterns
 */

export class MultiSessionCorrelationEngine {
  constructor() {
    this.sessionHistory = [];
    this.detectionAttempts = [];
    this.evasionPatterns = [];
    this.fingerprintHashes = [];
    this.storageKey = '__bot_detection_session_';
  }

  /**
   * Initialize multi-session tracking
   */
  initialize() {
    this.loadSessionHistory();
    this.recordCurrentSession();
  }

  /**
   * Load previous session data from storage
   */
  loadSessionHistory() {
    try {
      const stored = localStorage.getItem(this.storageKey + 'history');
      if (stored) {
        this.sessionHistory = JSON.parse(stored);
      }
    } catch (e) {
      // Ignore storage errors
    }
  }

  /**
   * Save current session to local storage
   */
  recordCurrentSession() {
    try {
      const sessionData = {
        timestamp: Date.now(),
        userAgent: navigator.userAgent,
        url: window.location.href,
        cookies: document.cookie.split(';').length
      };

      this.sessionHistory.push(sessionData);

      // Keep only last 30 sessions
      if (this.sessionHistory.length > 30) {
        this.sessionHistory = this.sessionHistory.slice(-30);
      }

      localStorage.setItem(this.storageKey + 'history', JSON.stringify(this.sessionHistory));
    } catch (e) {
      // Ignore storage errors
    }
  }

  /**
   * Record a detection attempt
   */
  recordDetectionAttempt(result, timeMs) {
    const attempt = {
      timestamp: Date.now(),
      score: result.score100 || 0,
      botScore: result.botScore || 0,
      riskLabel: result.riskLabel,
      signalCount: result.signals?.length || 0,
      elapsedMs: timeMs,
      userAgent: navigator.userAgent
    };

    this.detectionAttempts.push(attempt);

    // Keep only last 50 attempts
    if (this.detectionAttempts.length > 50) {
      this.detectionAttempts = this.detectionAttempts.slice(-50);
    }

    try {
      localStorage.setItem(
        this.storageKey + 'attempts',
        JSON.stringify(this.detectionAttempts)
      );
    } catch (e) {
      // Ignore
    }
  }

  /**
   * Compute fingerprint hash from browser signals
   */
  computeFingerprintHash(result) {
    try {
      const fingerprint = {
        ua: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory,
        timezone: new Date().getTimezoneOffset(),
        screenResolution: `${screen.width}x${screen.height}`,
        dpr: window.devicePixelRatio
      };

      // Simple hash
      const str = JSON.stringify(fingerprint);
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash; // Convert to 32bit integer
      }

      return Math.abs(hash).toString(16);
    } catch (e) {
      return 'unknown';
    }
  }

  /**
   * Detect evasion patterns across multiple detection runs
   * Indicators: score reduction, signal count changes, fingerprint changes
   */
  analyzeEvasionPattern() {
    const analysis = {
      detectionCount: this.detectionAttempts.length,
      avgScore: 0,
      scoreVariance: 0,
      scoreTrend: 'stable',
      evasionIndicators: [],
      likelyEvasionScore: 0
    };

    if (this.detectionAttempts.length < 2) {
      return analysis;
    }

    // Compute score statistics
    const scores = this.detectionAttempts.map(a => a.score);
    analysis.avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;

    const variance = scores.reduce((a, b) => a + Math.pow(b - analysis.avgScore, 2), 0) / scores.length;
    analysis.scoreVariance = Math.sqrt(variance);

    // Detect score trend (decreasing = evasion tuning)
    const firstScore = scores[0];
    const lastScore = scores[scores.length - 1];

    if (lastScore < firstScore - 5) {
      analysis.scoreTrend = 'decreasing';
      analysis.evasionIndicators.push({
        type: 'score-reduction-across-attempts',
        firstScore,
        lastScore,
        reduction: firstScore - lastScore,
        confidence: 0.72
      });
    } else if (lastScore > firstScore + 5) {
      analysis.scoreTrend = 'increasing';
    }

    // Detect rapid re-attempts (rate limiting bypass)
    if (this.detectionAttempts.length >= 2) {
      const timingGaps = [];
      for (let i = 1; i < this.detectionAttempts.length; i++) {
        const gap = this.detectionAttempts[i].timestamp - this.detectionAttempts[i - 1].timestamp;
        timingGaps.push(gap);
      }

      const avgGap = timingGaps.reduce((a, b) => a + b, 0) / timingGaps.length;
      const shortGaps = timingGaps.filter(g => g < 200).length;

      if (shortGaps > timingGaps.length * 0.5) {
        analysis.evasionIndicators.push({
          type: 'rapid-repeat-detection-attempts',
          avgGapMs: Math.round(avgGap),
          shortGapCount: shortGaps,
          confidence: 0.70
        });
      }
    }

    // Detect signal count fluctuation (bypassing detection)
    const signalCounts = this.detectionAttempts.map(a => a.signalCount);
    const signalVariance = signalCounts.reduce((a, b) => a + Math.pow(b - analysis.avgScore, 2), 0) / signalCounts.length;

    if (signalVariance > 10) {
      analysis.evasionIndicators.push({
        type: 'signal-count-fluctuation',
        variance: Math.round(signalVariance),
        confidence: 0.65
      });
    }

    // Detect fingerprint cycling (changing identity)
    const uniqueFingerprints = new Set(this.fingerprintHashes);
    if (uniqueFingerprints.size > 3 && this.detectionAttempts.length > 5) {
      analysis.evasionIndicators.push({
        type: 'fingerprint-cycling',
        uniqueCount: uniqueFingerprints.size,
        confidence: 0.68
      });
    }

    // Compute overall evasion likelihood
    if (analysis.evasionIndicators.length > 0) {
      const avgConfidence = analysis.evasionIndicators.reduce((a, i) => a + i.confidence, 0) /
                           analysis.evasionIndicators.length;
      analysis.likelyEvasionScore = Math.round(avgConfidence * 100);
    }

    return analysis;
  }

  /**
   * Detect detection circumvention attempts
   */
  detectDetectionCircumvention() {
    const indicators = [];

    try {
      // Check if detection functions are being blocked
      if (typeof window.runDetection === 'undefined') {
        indicators.push({
          type: 'detection-function-removed',
          confidence: 0.75
        });
      }

      // Check if error handling has been modified
      if (!window.onerror) {
        indicators.push({
          type: 'global-error-handler-disabled',
          confidence: 0.62
        });
      }

      // Check for console override (common in bots)
      if (!console.log.toString().includes('[native code]')) {
        indicators.push({
          type: 'console-methods-overridden',
          confidence: 0.70
        });
      }

      // Check for localStorage/sessionStorage access attempts
      try {
        localStorage.setItem('__test__', '__test__');
        localStorage.removeItem('__test__');
      } catch (e) {
        indicators.push({
          type: 'storage-access-blocked',
          confidence: 0.65
        });
      }

      // Check if fetch/XHR have been wrapped
      if (!fetch.toString().includes('[native code]')) {
        indicators.push({
          type: 'fetch-api-overridden',
          confidence: 0.73
        });
      }

      if (!XMLHttpRequest.toString().includes('[native code]')) {
        indicators.push({
          type: 'xmlhttprequest-overridden',
          confidence: 0.73
        });
      }
    } catch (e) {
      // Ignore
    }

    return indicators;
  }

  /**
   * Get overall multi-session analysis
   */
  getAnalysis() {
    return {
      sessionCount: this.sessionHistory.length,
      detectionAttemptCount: this.detectionAttempts.length,
      evasionPattern: this.analyzeEvasionPattern(),
      circumventionIndicators: this.detectDetectionCircumvention()
    };
  }

  /**
   * Check if this looks like a repeat evasion attempt
   */
  isLikelyRepeatEvasionAttempt() {
    const analysis = this.analyzeEvasionPattern();

    // Indicators of repeat evasion attempts
    if (analysis.detectionCount > 5 && analysis.lastScore < 30) {
      return true; // Multiple attempts, low scores = evasion tuning
    }

    if (analysis.evasionIndicators.some(i => i.type === 'score-reduction-across-attempts')) {
      return true; // Clearly tuning evasion
    }

    if (analysis.evasionIndicators.some(i => i.type === 'fingerprint-cycling')) {
      return true; // Changing fingerprint = evasion
    }

    return false;
  }

  /**
   * Clear all session history (for privacy)
   */
  clearHistory() {
    try {
      localStorage.removeItem(this.storageKey + 'history');
      localStorage.removeItem(this.storageKey + 'attempts');
      this.sessionHistory = [];
      this.detectionAttempts = [];
    } catch (e) {
      // Ignore
    }
  }
}

/**
 * Create correlation signal for detection system
 */
export function createMultiSessionSignal(analysis) {
  const { evasionPattern, circumventionIndicators } = analysis;

  if (evasionPattern.likelyEvasionScore > 60) {
    return {
      key: 'multiSessionEvasionPattern',
      label: 'Multi-Session Evasion Pattern Detected',
      value: true,
      evidence: evasionPattern,
      category: 'behavior',
      severity: 'hard',
      weight: 10,
      confidence: evasionPattern.likelyEvasionScore
    };
  }

  if (circumventionIndicators.length >= 2) {
    return {
      key: 'detectionCircumventionAttempt',
      label: 'Detection Circumvention Attempt',
      value: true,
      evidence: circumventionIndicators,
      category: 'integrity',
      severity: 'hard',
      weight: 9,
      confidence: Math.round(circumventionIndicators[0].confidence * 100)
    };
  }

  return null;
}

// Export singleton instance
export const multiSessionCorrelation = new MultiSessionCorrelationEngine();
