import { createDetectorResult, STATES } from '../schema/detectorTypes.js';

/**
 * Anti-Detection Detection Module
 * Detects attempts to disable, block, or circumvent bot detection
 */

function detectDetectionScriptShadowing() {
  const signals = [];

  try {
    // Check if detection script functions are shadowed/intercepted
    if (typeof window.runDetection === 'function') {
      const funcStr = window.runDetection.toString();

      // Native detection function should not be wrapped
      if (!funcStr.includes('detectBot') && !funcStr.includes('runDetectionBtn')) {
        signals.push({
          type: 'detection-function-wrapped',
          confidence: 0.72
        });
      }

      // Check for proxy interception
      const descriptor = Object.getOwnPropertyDescriptor(window, 'runDetection');
      if (descriptor && descriptor.get && !descriptor.get.toString().includes('[native code]')) {
        signals.push({
          type: 'detection-function-getter-patched',
          confidence: 0.75
        });
      }
    }

    // Check if detection result is being modified
    if (window.lastDetectionResults) {
      const resultsStr = JSON.stringify(window.lastDetectionResults);
      // Check if results object seems modified
      if (resultsStr.length < 100) {
        signals.push({
          type: 'detection-results-truncated',
          confidence: 0.65
        });
      }
    }
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectErrorSuppression() {
  const signals = [];

  try {
    // Check if global error handler is disabled
    const hasErrorHandler = window.onerror !== null;
    if (!hasErrorHandler) {
      signals.push({
        type: 'global-error-handler-disabled',
        confidence: 0.60
      });
    }

    // Check if error events are intercepted
    let errorThrown = false;
    const handler = () => { errorThrown = true; };
    window.addEventListener('error', handler);

    try {
      throw new Error('detection-test');
    } catch (e) {
      // Expected
    }

    if (!errorThrown) {
      signals.push({
        type: 'error-events-intercepted',
        confidence: 0.70
      });
    }

    window.removeEventListener('error', handler);

    // Check if unhandled promise rejections are being suppressed
    let rejectionHandled = false;
    const rejectionHandler = (event) => { rejectionHandled = true; };
    window.addEventListener('unhandledrejection', rejectionHandler);

    Promise.reject(new Error('detection-test')).catch(() => {});

    setTimeout(() => {
      if (!rejectionHandled) {
        signals.push({
          type: 'unhandled-rejection-suppression',
          confidence: 0.68
        });
      }
      window.removeEventListener('unhandledrejection', rejectionHandler);
    }, 100);
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectNetworkInterception() {
  const signals = [];

  try {
    // Check if service worker is installed (could intercept requests)
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then(registrations => {
        if (registrations.length > 0) {
          signals.push({
            type: 'service-worker-registered',
            count: registrations.length,
            confidence: 0.62
          });
        }
      }).catch(() => {
        // Service worker access might be intentionally blocked
        signals.push({
          type: 'service-worker-access-blocked',
          confidence: 0.58
        });
      });
    }

    // Check if fetch is intercepted
    const fetchStr = String(fetch);
    if (!fetchStr.includes('[native code]')) {
      signals.push({
        type: 'fetch-intercepted',
        confidence: 0.75
      });
    }

    // Check if XMLHttpRequest is intercepted
    const xhrStr = String(XMLHttpRequest.prototype.open);
    if (!xhrStr.includes('[native code]')) {
      signals.push({
        type: 'xmlhttprequest-intercepted',
        confidence: 0.75
      });
    }

    // Test for request header modification
    try {
      const testHeaders = new Headers({
        'X-Detection-Test': 'true'
      });

      const testReq = new Request('about:blank', { headers: testHeaders });
      if (!testReq.headers.has('X-Detection-Test')) {
        signals.push({
          type: 'request-headers-modified',
          confidence: 0.70
        });
      }
    } catch (e) {
      // Headers test failed
    }
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectEventListenerHijacking() {
  const signals = [];

  try {
    // Check if addEventListener has been patched
    const addEventListenerStr = EventTarget.prototype.addEventListener.toString();
    if (!addEventListenerStr.includes('[native code]')) {
      signals.push({
        type: 'event-listener-patched',
        confidence: 0.73
      });
    }

    // Check if event properties are being intercepted
    const testEvent = new MouseEvent('test');
    const descriptor = Object.getOwnPropertyDescriptor(testEvent, 'clientX');

    if (descriptor?.get && !descriptor.get.toString().includes('[native code]')) {
      signals.push({
        type: 'event-property-getter-patched',
        confidence: 0.70
      });
    }

    // Check if wheel event is blocked
    let wheelEventFired = false;
    const wheelHandler = () => { wheelEventFired = true; };
    window.addEventListener('wheel', wheelHandler);

    const wheelEvent = new WheelEvent('wheel', { deltaY: 10 });
    window.dispatchEvent(wheelEvent);

    if (!wheelEventFired) {
      signals.push({
        type: 'wheel-event-suppressed',
        confidence: 0.65
      });
    }

    window.removeEventListener('wheel', wheelHandler);
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectElementModification() {
  const signals = [];

  try {
    // Check if DOM element creation is monitored
    const testElement = document.createElement('div');

    // Check if element properties are patched
    const classNameDescriptor = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(testElement),
      'className'
    );

    if (classNameDescriptor?.set && !classNameDescriptor.set.toString().includes('[native code]')) {
      signals.push({
        type: 'element-property-setter-patched',
        confidence: 0.68
      });
    }

    // Check if DOM events on detection elements are hijacked
    const detectionBtn = document.getElementById('runDetectionBtn');
    if (detectionBtn) {
      const clickDescriptor = Object.getOwnPropertyDescriptor(detectionBtn, 'onclick');
      if (clickDescriptor?.get && !clickDescriptor.get.toString().includes('[native code]')) {
        signals.push({
          type: 'detection-button-click-hijacked',
          confidence: 0.75
        });
      }
    }

    // Check if innerHTML/textContent modifications are intercepted
    const originalInnerHTML = Object.getOwnPropertyDescriptor(
      HTMLElement.prototype,
      'innerHTML'
    );

    if (originalInnerHTML?.set && !originalInnerHTML.set.toString().includes('[native code]')) {
      signals.push({
        type: 'html-content-modification-patched',
        confidence: 0.70
      });
    }
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectObjectFreezing() {
  const signals = [];

  try {
    // Check if critical objects are frozen/sealed (prevents bot modifications)
    const criticalObjects = [
      navigator,
      window.top,
      document,
      Object.prototype
    ];

    criticalObjects.forEach((obj, idx) => {
      if (obj && Object.isFrozen(obj)) {
        signals.push({
          type: 'critical-object-frozen',
          object: ['navigator', 'window.top', 'document', 'Object.prototype'][idx],
          confidence: 0.72
        });
      }

      if (obj && Object.isSealed(obj)) {
        signals.push({
          type: 'critical-object-sealed',
          object: ['navigator', 'window.top', 'document', 'Object.prototype'][idx],
          confidence: 0.68
        });
      }
    });
  } catch (err) {
    // Ignore
  }

  return signals;
}

function detectStorageModification() {
  const signals = [];

  try {
    // Check if localStorage/sessionStorage are monitored/blocked
    try {
      localStorage.setItem('__anti_bot_test__', 'test');
      localStorage.removeItem('__anti_bot_test__');
    } catch (e) {
      signals.push({
        type: 'local-storage-access-restricted',
        confidence: 0.70
      });
    }

    // Check if storage events are triggered
    let storageEventFired = false;
    const storageHandler = () => { storageEventFired = true; };
    window.addEventListener('storage', storageHandler);

    try {
      localStorage.setItem('__fire_event_test__', 'test');
      localStorage.removeItem('__fire_event_test__');
    } catch (e) {
      // Ignore
    }

    setTimeout(() => {
      if (!storageEventFired && navigator.userAgent.includes('Chrome')) {
        signals.push({
          type: 'storage-events-not-firing',
          confidence: 0.60
        });
      }
      window.removeEventListener('storage', storageHandler);
    }, 100);
  } catch (err) {
    // Ignore
  }

  return signals;
}

export function runAntiDetectionDetection() {
  const signals = [];
  const evidence = {};

  // Detect script shadowing
  const scriptShadowing = detectDetectionScriptShadowing();
  evidence.scriptShadowing = scriptShadowing;

  if (scriptShadowing.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'detectionScriptShadowed',
        label: 'Detection Script Shadowing/Interception',
        value: true,
        evidence: scriptShadowing,
        category: 'integrity',
        severity: 'hard',
        weight: 9,
        confidence: Math.round(scriptShadowing[0].confidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Detect error suppression
  const errorSuppression = detectErrorSuppression();
  evidence.errorSuppression = errorSuppression;

  if (errorSuppression.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'errorSuppressionDetected',
        label: 'Error Suppression/Interception',
        value: true,
        evidence: errorSuppression,
        category: 'integrity',
        severity: 'hard',
        weight: 8,
        confidence: Math.round(errorSuppression[0].confidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Detect network interception
  const networkInterception = detectNetworkInterception();
  evidence.networkInterception = networkInterception;

  if (networkInterception.length >= 2) {
    signals.push(
      createDetectorResult({
        key: 'networkInterceptionDetected',
        label: 'Network Request Interception',
        value: true,
        evidence: networkInterception,
        category: 'integrity',
        severity: 'hard',
        weight: 8,
        confidence: Math.round(networkInterception[0].confidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Detect event listener hijacking
  const eventHijacking = detectEventListenerHijacking();
  evidence.eventHijacking = eventHijacking;

  if (eventHijacking.length >= 2) {
    signals.push(
      createDetectorResult({
        key: 'eventListenerHijackingDetected',
        label: 'Event Listener Hijacking',
        value: true,
        evidence: eventHijacking,
        category: 'integrity',
        severity: 'hard',
        weight: 8,
        confidence: Math.round(eventHijacking[0].confidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Detect element modification
  const elementMod = detectElementModification();
  evidence.elementModification = elementMod;

  if (elementMod.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'elementModificationDetected',
        label: 'DOM Element Modification Detection',
        value: true,
        evidence: elementMod,
        category: 'integrity',
        severity: 'hard',
        weight: 8,
        confidence: Math.round(elementMod[0].confidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Detect object freezing
  const objectFreezing = detectObjectFreezing();
  evidence.objectFreezing = objectFreezing;

  if (objectFreezing.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'criticalObjectFrozen',
        label: 'Critical Object Frozen (Anti-Modification)',
        value: true,
        evidence: objectFreezing,
        category: 'integrity',
        severity: 'soft',
        weight: 5,
        confidence: Math.round(objectFreezing[0].confidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Detect storage modification/access issues
  const storageMod = detectStorageModification();
  evidence.storageModification = storageMod;

  if (storageMod.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'storageAccessRestricted',
        label: 'Storage Access Restrictions Detected',
        value: true,
        evidence: storageMod,
        category: 'integrity',
        severity: 'soft',
        weight: 4,
        confidence: Math.round(storageMod[0].confidence * 100),
        state: 'suspicious'
      })
    );
  }

  return { signals, evidence };
}
