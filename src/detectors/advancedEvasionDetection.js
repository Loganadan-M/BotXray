import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';

/**
 * Advanced Evasion Detection Module
 * Detects sophisticated bot evasion techniques including:
 * - Memory pattern anomalies
 * - API call sequence violations
 * - Performance.now() precision attacks
 * - Proxy-based property patching
 * - Error stack sanitization
 * - Console/Network interception
 */

function detectProxyPatchers() {
  const signals = [];
  const suspects = ['navigator', 'window', 'Object', 'Function'];

  try {
    suspects.forEach(suspect => {
      const target = eval(suspect);
      if (!target) return;

      // Check if object has been wrapped in Proxy
      const descriptor = Object.getOwnPropertyDescriptor(target, Symbol.toStringTag);
      if (descriptor && descriptor.configurable === false && descriptor.writable !== true) {
        // Likely a proxy or heavily modified object
        signals.push({
          type: 'proxy-wrapped-object',
          target: suspect,
          confidence: 0.7
        });
      }

      // Check for function property getter interception
      const props = Object.getOwnPropertyNames(target);
      let patchedCount = 0;
      props.slice(0, 10).forEach(prop => {
        const desc = Object.getOwnPropertyDescriptor(target, prop);
        if (desc && desc.get && desc.get.toString().includes('[native code]') === false) {
          patchedCount++;
        }
      });

      if (patchedCount >= 2) {
        signals.push({
          type: 'non-native-getters',
          target: suspect,
          patchedCount,
          confidence: 0.65
        });
      }
    });
  } catch (err) {
    // Ignore errors during introspection
  }

  return signals;
}

function detectPerformanceTimingAnomaly() {
  const samples = [];
  const baseline = performance.now();

  try {
    for (let i = 0; i < 10; i++) {
      const now = performance.now();
      samples.push(now - baseline);
    }

    // Check for suspiciously regular timing (mocked performance.now())
    const diffs = [];
    for (let i = 1; i < samples.length; i++) {
      diffs.push(samples[i] - samples[i - 1]);
    }

    const avgDiff = diffs.reduce((a, b) => a + b, 0) / diffs.length;
    const variance = diffs.reduce((a, b) => a + Math.pow(b - avgDiff, 2), 0) / diffs.length;
    const stdDev = Math.sqrt(variance);

    // Artificially mocked performance.now() has very low variance
    if (stdDev < 0.1 && avgDiff > 0.5) {
      return {
        detected: true,
        anomaly: 'suspiciously-low-timing-variance',
        stdDev,
        avgDiff,
        confidence: 0.72
      };
    }

    // Check for timing precision > milliseconds (indicates precision spoofing)
    const fractionalParts = samples.map(s => s % 1);
    const uniqueFractions = new Set(fractionalParts.map(f => f.toFixed(3)));
    if (uniqueFractions.size === 1) {
      return {
        detected: true,
        anomaly: 'identical-fractional-timing',
        confidence: 0.68
      };
    }
  } catch (err) {
    // Ignore
  }

  return { detected: false };
}

function detectFetchXhrInterception() {
  const signals = [];

  try {
    // Check if fetch is wrapped
    const fetchStr = fetch.toString();
    if (!fetchStr.includes('[native code]')) {
      signals.push({
        type: 'fetch-intercepted',
        confidence: 0.75
      });
    }

    // Check if XMLHttpRequest is patched
    const xhrStr = XMLHttpRequest.toString();
    if (!xhrStr.includes('[native code]')) {
      signals.push({
        type: 'xmlhttprequest-intercepted',
        confidence: 0.75
      });
    }

    // Check for service worker interception indicators
    if ('serviceWorker' in navigator) {
      const swRegistrations = navigator.serviceWorker.getRegistrations?.toString();
      if (swRegistrations && !swRegistrations.includes('[native code]')) {
        signals.push({
          type: 'service-worker-intercepted',
          confidence: 0.70
        });
      }
    }

    // Check request object prototype chain
    try {
      const testReq = new XMLHttpRequest();
      const setReqHeaderStr = testReq.setRequestHeader.toString();
      if (!setReqHeaderStr.includes('[native code]')) {
        signals.push({
          type: 'request-method-patched',
          method: 'setRequestHeader',
          confidence: 0.73
        });
      }
    } catch (e) {
      // Ignore
    }
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectErrorStackManipulation() {
  const signals = [];

  try {
    const testError = new Error('test');
    const stackStr = String(testError.stack || '');

    // Check for sanitized/empty stacks
    if (stackStr.length === 0) {
      signals.push({
        type: 'error-stack-sanitized',
        confidence: 0.60
      });
    }

    // Check for stack without function names
    const hasNativeMarker = /at native|[native code]|\<anonymous\>/.test(stackStr);
    const hasValidFunctionNames = /at\s+\w+\s*\(/.test(stackStr);

    if (hasNativeMarker && !hasValidFunctionNames) {
      signals.push({
        type: 'suspicious-stack-format',
        confidence: 0.58
      });
    }

    // Check for repeated stack lines (indicates template-based stacks)
    const lines = stackStr.split('\n');
    if (lines.length > 3) {
      const firstLine = lines[1] || '';
      const repeats = lines.filter(l => l === firstLine).length;
      if (repeats >= 2) {
        signals.push({
          type: 'repeated-stack-lines',
          confidence: 0.55
        });
      }
    }

    // Check Error constructor patching
    const errConstructorStr = Error.toString();
    if (!errConstructorStr.includes('[native code]')) {
      signals.push({
        type: 'error-constructor-patched',
        confidence: 0.65
      });
    }
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectAPISequenceAnomaly(apiCallHistory) {
  const signals = [];

  if (!Array.isArray(apiCallHistory) || apiCallHistory.length < 3) {
    return signals;
  }

  // Define expected API sequences for normal users
  const suspiciousSequences = [
    // Bot checks for detection immediately
    ['navigator.webdriver', 'window.eval', 'Function.toString'],
    // Rapid property access without usage
    ['navigator.platform', 'navigator.hardwareConcurrency', 'navigator.deviceMemory', 'navigator.maxTouchPoints'],
    // Accessing usually hidden properties
    ['Object.getOwnPropertyNames', 'window.eval', 'Object.getOwnPropertyDescriptor'],
  ];

  suspiciousSequences.forEach(pattern => {
    let matchIndex = 0;
    for (let i = 0; i < apiCallHistory.length && matchIndex < pattern.length; i++) {
      if (apiCallHistory[i].includes(pattern[matchIndex])) {
        matchIndex++;
      }
    }
    if (matchIndex === pattern.length) {
      signals.push({
        type: 'suspicious-api-sequence',
        pattern: pattern.join(' → '),
        confidence: 0.68
      });
    }
  });

  return signals;
}

function detectMemorySignatures() {
  const signals = [];

  try {
    // Check for headless-specific memory patterns
    const memoryInfo = performance.memory;
    if (!memoryInfo) return signals;

    const { jsHeapSizeLimit, totalJSHeapSize, usedJSHeapSize } = memoryInfo;

    // Check for suspiciously small heap (headless browsers often have small heaps)
    if (usedJSHeapSize && jsHeapSizeLimit) {
      const heapRatio = usedJSHeapSize / jsHeapSizeLimit;

      // If using <30% of available heap, might be headless
      if (heapRatio < 0.3) {
        signals.push({
          type: 'low-heap-utilization',
          ratio: heapRatio,
          confidence: 0.52
        });
      }

      // Check for exact round numbers (VM allocation patterns)
      if (Number.isInteger(jsHeapSizeLimit / (1024 * 1024))) {
        const sizeInMB = jsHeapSizeLimit / (1024 * 1024);
        const suspiciousSizes = [128, 256, 512, 1024];
        if (suspiciousSizes.includes(sizeInMB)) {
          signals.push({
            type: 'vm-like-heap-size',
            sizeInMB,
            confidence: 0.55
          });
        }
      }
    }
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectConsoleInterception() {
  const signals = [];

  try {
    // Check if console methods are overridden
    const consoleMethods = ['log', 'warn', 'error', 'debug', 'info'];
    let interceptedCount = 0;

    consoleMethods.forEach(method => {
      const methodStr = console[method].toString();
      if (!methodStr.includes('[native code]')) {
        interceptedCount++;
      }
    });

    if (interceptedCount >= 2) {
      signals.push({
        type: 'console-methods-intercepted',
        count: interceptedCount,
        confidence: 0.70
      });
    }

    // Check if console.assert is overridden (common in bot frameworks)
    if (console.assert && !console.assert.toString().includes('[native code]')) {
      signals.push({
        type: 'console-assert-patched',
        confidence: 0.65
      });
    }
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectUndetectableChromedriver() {
  const signals = [];

  try {
    // Check for undetected-chromedriver specific patterns
    // These bypass standard webdriver detection but leave subtle traces

    // 1. Check for modified Object.getOwnPropertyDescriptor (often patched)
    const testObj = {};
    const descStr = Object.getOwnPropertyDescriptor.toString();
    if (!descStr.includes('[native code]')) {
      signals.push({
        type: 'object-getownpropertydescriptor-patched',
        confidence: 0.68
      });
    }

    // 2. Check for missing or modified chrome.runtime
    if (window.chrome && window.chrome.runtime) {
      const runtimeStr = window.chrome.runtime.sendMessage?.toString();
      if (runtimeStr && !runtimeStr.includes('[native code]')) {
        signals.push({
          type: 'chrome-runtime-patched',
          confidence: 0.70
        });
      }
    }

    // 3. Check for stealth plugin patterns (puppeteer-extra-plugin-stealth)
    const hasHiddenFunctions = !('__hiddenProperties__' in window) &&
                               Object.getOwnPropertyNames(window).length > 0;

    // 4. Check for languages array manipulation (common in undetected-chromedriver)
    const langStr = navigator.languages.toString();
    if (!langStr.includes(',') && navigator.languages.length > 1) {
      signals.push({
        type: 'languages-array-anomaly',
        confidence: 0.62
      });
    }

    // 5. Check for user-agent data anomalies
    try {
      const uaData = navigator.userAgentData;
      if (uaData && uaData.brands) {
        const hasHeadlessInBrand = uaData.brands.some(b => /headless/i.test(b.brand));
        if (hasHeadlessInBrand) {
          signals.push({
            type: 'headless-in-ua-brands',
            confidence: 0.75
          });
        }
      }
    } catch (e) {
      // Ignore
    }
  } catch (err) {
    // Ignore
  }

  return signals;
}

export function runAdvancedEvasionDetection() {
  const signals = [];
  const evidence = {
    proxyPatchers: [],
    performanceAnomalies: {},
    fetchXhrInterception: [],
    errorStackAnomalies: [],
    apiSequenceAnomalies: [],
    memorySignatures: [],
    consoleInterception: [],
    undetectablePatterns: []
  };

  // Detect proxy-based patching
  const proxySignals = detectProxyPatchers();
  evidence.proxyPatchers = proxySignals;
  if (proxySignals.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'advancedProxyPatching',
        label: 'Proxy-Based Property Patching',
        value: true,
        evidence: proxySignals,
        category: 'integrity',
        severity: 'hard',
        weight: 8,
        confidence: 70,
        state: 'suspicious'
      })
    );
  }

  // Detect performance.now() anomalies
  const perfAnomaly = detectPerformanceTimingAnomaly();
  evidence.performanceAnomalies = perfAnomaly;
  if (perfAnomaly.detected) {
    signals.push(
      createDetectorResult({
        key: 'performanceNowSpoofing',
        label: 'Performance.now() Anomaly Detection',
        value: true,
        evidence: perfAnomaly,
        category: 'integrity',
        severity: 'hard',
        weight: 7,
        confidence: Math.round(perfAnomaly.confidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Detect fetch/XHR interception
  const fetchSignals = detectFetchXhrInterception();
  evidence.fetchXhrInterception = fetchSignals;
  if (fetchSignals.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'fetchXhrIntercepted',
        label: 'Network API Interception',
        value: true,
        evidence: fetchSignals,
        category: 'integrity',
        severity: 'hard',
        weight: 8,
        confidence: Math.min(...fetchSignals.map(s => s.confidence)) * 100,
        state: 'suspicious'
      })
    );
  }

  // Detect error stack manipulation
  const stackSignals = detectErrorStackManipulation();
  evidence.errorStackAnomalies = stackSignals;
  if (stackSignals.length >= 2) {
    signals.push(
      createDetectorResult({
        key: 'errorStackManipulation',
        label: 'Error Stack Manipulation',
        value: true,
        evidence: stackSignals,
        category: 'integrity',
        severity: 'hard',
        weight: 7,
        confidence: 68,
        state: 'suspicious'
      })
    );
  }

  // Detect console interception
  const consoleSignals = detectConsoleInterception();
  evidence.consoleInterception = consoleSignals;
  if (consoleSignals.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'consoleIntercepted',
        label: 'Console API Interception',
        value: true,
        evidence: consoleSignals,
        category: 'integrity',
        severity: 'hard',
        weight: 6,
        confidence: 70,
        state: 'suspicious'
      })
    );
  }

  // Detect Undetected-Chromedriver patterns
  const undetectableSignals = detectUndetectableChromedriver();
  evidence.undetectablePatterns = undetectableSignals;
  if (undetectableSignals.length >= 2) {
    signals.push(
      createDetectorResult({
        key: 'undetectedChromedriverPatterns',
        label: 'Undetected-Chromedriver Indicators',
        value: true,
        evidence: undetectableSignals,
        category: 'automation',
        severity: 'hard',
        weight: 9,
        confidence: Math.min(...undetectableSignals.map(s => s.confidence)) * 100,
        state: 'suspicious'
      })
    );
  }

  // Detect memory signatures
  const memorySignals = detectMemorySignatures();
  evidence.memorySignatures = memorySignals;
  if (memorySignals.length >= 2) {
    signals.push(
      createDetectorResult({
        key: 'headlessBrowserMemorySignature',
        label: 'Headless Browser Memory Patterns',
        value: true,
        evidence: memorySignals,
        category: 'environment',
        severity: 'soft',
        weight: 4,
        confidence: 60,
        state: 'suspicious'
      })
    );
  }

  return { signals, evidence };
}
