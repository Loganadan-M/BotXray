import { createDetectorResult, STATES } from '../schema/detectorTypes.js';

/**
 * API Call Sequencing and Integrity Checks
 * Detects unusual API call patterns and sequencing used by bots
 */

let apiCallHistory = [];
let apiCallPatterns = {
  detectionAPICalls: [],
  suspiciousSequences: [],
  apiAccessTimings: []
};

function initializeAPITracking() {
  try {
    // Track property access patterns
    const trackedObjects = {
      'navigator': navigator,
      'window': window,
      'document': document,
      'Object': Object,
      'Function': Function,
      'performance': performance
    };

    Object.entries(trackedObjects).forEach(([objName, obj]) => {
      if (!obj) return;

      // Use Proxy to track property access (if not already proxied)
      try {
        const handler = {
          get(target, prop) {
            recordAPICall(`${objName}.${String(prop)}`);
            return Reflect.get(target, prop);
          }
        };

        // Only proxy if not already proxied
        if (!target[Symbol.toStringTag]?.includes('Proxy')) {
          // Skip proxying to avoid recursion
        }
      } catch (e) {
        // Ignore proxying errors
      }
    });

    // Track navigator property access
    const navigatorProps = [
      'webdriver', 'platform', 'hardwareConcurrency', 'deviceMemory',
      'maxTouchPoints', 'languages', 'language', 'userAgent', 'plugins',
      'mimeTypes', 'permissions', 'geolocation', 'clipboard'
    ];

    navigatorProps.forEach(prop => {
      try {
        const desc = Object.getOwnPropertyDescriptor(navigator, prop);
        if (!desc) {
          // Try prototype
          const protoDesc = Object.getOwnPropertyDescriptor(
            Object.getPrototypeOf(navigator),
            prop
          );

          if (protoDesc && protoDesc.get) {
            const originalGetter = protoDesc.get;
            Object.defineProperty(navigator, prop, {
              get() {
                recordAPICall(`navigator.${prop}`);
                return originalGetter.call(this);
              }
            });
          }
        }
      } catch (e) {
        // Ignore
      }
    });
  } catch (err) {
    // Initialization error
  }
}

function recordAPICall(apiName) {
  apiCallHistory.push({
    api: apiName,
    time: performance.now(),
    stack: new Error().stack?.split('\n')[3] || 'unknown'
  });

  // Keep history limited
  if (apiCallHistory.length > 200) {
    apiCallHistory = apiCallHistory.slice(-200);
  }
}

function detectDetectionAPIAccess() {
  const detectionAPIs = [
    'navigator.webdriver',
    'window.eval',
    'Function.toString',
    'Object.getOwnPropertyDescriptor',
    'Object.getOwnPropertyNames',
    'window.chrome',
    'navigator.permissions',
    'performance.memory',
    'navigator.hardwareConcurrency',
    'Object.defineProperty'
  ];

  const accessedDetectionAPIs = apiCallHistory.filter(call =>
    detectionAPIs.some(api => call.api === api)
  );

  // Check if all detector APIs accessed in sequence
  const accessOrder = accessedDetectionAPIs.map(c => c.api);
  const suspiciousPatterns = [
    ['navigator.webdriver', 'window.eval', 'Function.toString'],
    ['Object.getOwnPropertyDescriptor', 'navigator.permissions', 'window.eval'],
    ['navigator.hardwareConcurrency', 'navigator.deviceMemory', 'navigator.maxTouchPoints']
  ];

  const detectedPatterns = [];
  suspiciousPatterns.forEach(pattern => {
    let matchIndex = 0;
    for (let i = 0; i < accessOrder.length && matchIndex < pattern.length; i++) {
      if (accessOrder[i] === pattern[matchIndex]) {
        matchIndex++;
      }
    }
    if (matchIndex === pattern.length) {
      detectedPatterns.push(pattern);
    }
  });

  apiCallPatterns.detectionAPICalls = {
    accessedAPIs: accessedDetectionAPIs.length,
    detectionAPIsCount: accessedDetectionAPIs.length,
    suspiciousPatterns: detectedPatterns
  };

  return {
    hasDetectionAPICalls: accessedDetectionAPIs.length > 0,
    patternsDetected: detectedPatterns.length,
    evidence: apiCallPatterns.detectionAPICalls
  };
}

function detectAPICooccurrenceAnomalies() {
  const anomalies = [];

  // Some APIs should be accessed together (co-occurrence)
  const cooccurrenceRules = [
    {
      name: 'memory-detection-pattern',
      apis: ['navigator.hardwareConcurrency', 'navigator.deviceMemory'],
      minCount: 2,
      maxGapMs: 100
    },
    {
      name: 'permissions-detection-pattern',
      apis: ['navigator.permissions', 'navigator.permissions.query'],
      minCount: 2,
      maxGapMs: 50
    },
    {
      name: 'chrome-object-check',
      apis: ['window.chrome', 'window.chrome.runtime'],
      minCount: 2,
      maxGapMs: 200
    }
  ];

  cooccurrenceRules.forEach(rule => {
    const matchedIndices = [];
    apiCallHistory.forEach((call, idx) => {
      if (rule.apis.some(api => call.api === api)) {
        matchedIndices.push(idx);
      }
    });

    // Check if all APIs accessed and within time window
    const ruleAPIsAccessed = new Set(
      apiCallHistory
        .filter((_, idx) => matchedIndices.includes(idx))
        .map(call => call.api)
    );

    if (ruleAPIsAccessed.size === rule.apis.length && matchedIndices.length >= rule.minCount) {
      const timeGaps = [];
      for (let i = 1; i < matchedIndices.length; i++) {
        timeGaps.push(
          apiCallHistory[matchedIndices[i]].time - apiCallHistory[matchedIndices[i - 1]].time
        );
      }

      const maxGap = Math.max(...timeGaps);
      if (maxGap <= rule.maxGapMs) {
        anomalies.push({
          rule: rule.name,
          confidence: 0.68,
          maxGapMs: maxGap
        });
      }
    }
  });

  return anomalies;
}

function detectRapidAPIAccess() {
  const rapidAccesses = [];

  // Group API calls by 100ms windows
  const windows = {};
  apiCallHistory.forEach(call => {
    const windowKey = Math.floor(call.time / 100);
    if (!windows[windowKey]) windows[windowKey] = [];
    windows[windowKey].push(call);
  });

  // Find windows with excessive API calls
  Object.entries(windows).forEach(([key, calls]) => {
    if (calls.length > 20) {
      // More than 20 API calls in 100ms is suspicious
      rapidAccesses.push({
        window: key,
        callCount: calls.length,
        apis: [...new Set(calls.map(c => c.api))],
        confidence: 0.65
      });
    }
  });

  return rapidAccesses;
}

function detectUnusualPropertyAccess() {
  const unusual = [];

  // Properties that bots check but normal users rarely do
  const botLikeProperties = [
    'arguments.callee',
    'eval',
    'Function.constructor',
    'Object.getOwnPropertyDescriptor',
    'Object.defineProperty',
    'window.webkitRequestAnimationFrame',
    'navigator.vendor',
    'window.controller'
  ];

  const accessedBotLikeProps = apiCallHistory.filter(call =>
    botLikeProperties.some(prop => call.api === prop)
  );

  if (accessedBotLikeProps.length >= 3) {
    unusual.push({
      type: 'bot-like-property-access',
      count: accessedBotLikeProps.length,
      confidence: 0.62
    });
  }

  return unusual;
}

function validateAPIIntegrity() {
  const issues = [];

  try {
    // Check if Object.getOwnPropertyDescriptor has been patched
    if (!Object.getOwnPropertyDescriptor.toString().includes('[native code]')) {
      issues.push({
        type: 'object-getownpropertydescriptor-patched',
        confidence: 0.70
      });
    }

    // Check if Object.defineProperty has been patched
    if (!Object.defineProperty.toString().includes('[native code]')) {
      issues.push({
        type: 'object-defineproperty-patched',
        confidence: 0.70
      });
    }

    // Check if Function.prototype.toString  has been patched
    const funcStr = Function.prototype.toString.toString();
    if (!funcStr.includes('[native code]')) {
      issues.push({
        type: 'function-tostring-patched',
        confidence: 0.75
      });
    }

    // Check navigator.permissions.query integrity
    try {
      if (navigator.permissions && navigator.permissions.query) {
        const permStr = navigator.permissions.query.toString();
        if (!permStr.includes('[native code]')) {
          issues.push({
            type: 'permissions-query-patched',
            confidence: 0.68
          });
        }
      }
    } catch (e) {
      // Ignore
    }

    // Check constructor integrity
    const testObj = {};
    const constructorStr = testObj.constructor.toString();
    if (!constructorStr.includes('[native code]')) {
      issues.push({
        type: 'object-constructor-patched',
        confidence: 0.65
      });
    }
  } catch (err) {
    // Ignore
  }

  return issues;
}

export function initAPISequencingDetection() {
  initializeAPITracking();
}

export function getAPICallHistory() {
  return apiCallHistory.slice();
}

export function runAPISequencingChecks() {
  const signals = [];
  const evidence = {};

  // Detect detection API access
  const detectionAccess = detectDetectionAPIAccess();
  evidence.detectionAPIAccess = detectionAccess;

  if (detectionAccess.patternsDetected > 0) {
    signals.push(
      createDetectorResult({
        key: 'suspiciousDetectionAPISequence',
        label: 'Suspicious Detection API Sequence',
        value: true,
        evidence: detectionAccess.evidence,
        category: 'integrity',
        severity: 'hard',
        weight: 8,
        confidence: 72,
        state: 'suspicious'
      })
    );
  }

  // Detect API co-occurrence anomalies
  const cooccurrenceAnomalies = detectAPICooccurrenceAnomalies();
  evidence.cooccurrenceAnomalies = cooccurrenceAnomalies;

  if (cooccurrenceAnomalies.length >= 2) {
    signals.push(
      createDetectorResult({
        key: 'apiCooccurrenceAnomaly',
        label: 'API Co-occurrence Anomaly',
        value: true,
        evidence: cooccurrenceAnomalies,
        category: 'integrity',
        severity: 'soft',
        weight: 6,
        confidence: 65,
        state: 'suspicious'
      })
    );
  }

  // Detect rapid API access
  const rapidAccess = detectRapidAPIAccess();
  evidence.rapidAPIAccess = rapidAccess;

  if (rapidAccess.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'rapidAPIAccess',
        label: 'Rapid API Access Pattern',
        value: true,
        evidence: rapidAccess,
        category: 'integrity',
        severity: 'soft',
        weight: 5,
        confidence: 62,
        state: 'suspicious'
      })
    );
  }

  // Detect unusual property access
  const unusualAccess = detectUnusualPropertyAccess();
  evidence.unusualPropertyAccess = unusualAccess;

  if (unusualAccess.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'unusualPropertyAccess',
        label: 'Unusual Property Access Pattern',
        value: true,
        evidence: unusualAccess,
        category: 'integrity',
        severity: 'soft',
        weight: 5,
        confidence: 60,
        state: 'suspicious'
      })
    );
  }

  // Validate API integrity
  const integrityIssues = validateAPIIntegrity();
  evidence.apiIntegrityIssues = integrityIssues;

  if (integrityIssues.length >= 2) {
    signals.push(
      createDetectorResult({
        key: 'multipleAPIIntegrityIssues',
        label: 'Multiple API Integrity Issues',
        value: true,
        evidence: integrityIssues,
        category: 'integrity',
        severity: 'hard',
        weight: 8,
        confidence: 68,
        state: 'suspicious'
      })
    );
  }

  return { signals, evidence };
}
