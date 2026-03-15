import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';
import { safeToString } from '../utils/common.js';
import { NATIVE_REFS, isFunctionLikelyNative } from '../utils/nativeRefs.js';

function getterLooksNonNative(target, prop) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(target, prop);
    if (!descriptor || typeof descriptor.get !== 'function') return false;
    const source = safeToString(descriptor.get);
    return !source.includes('[native code]');
  } catch (error) {
    return false;
  }
}

function collectPatchedGetterSignals() {
  const hits = [];
  ['platform', 'languages', 'language', 'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints', 'webdriver', 'plugins', 'mimeTypes'].forEach(prop => {
    if (getterLooksNonNative(Navigator.prototype, prop)) hits.push(`Navigator.prototype.${prop}`);
  });

  ['innerWidth', 'innerHeight', 'outerWidth', 'outerHeight', 'devicePixelRatio'].forEach(prop => {
    if (getterLooksNonNative(window, prop)) hits.push(`window.${prop}`);
  });

  ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'].forEach(prop => {
    if (getterLooksNonNative(window.screen, prop)) hits.push(`screen.${prop}`);
  });

  ['visibilityState', 'hidden', 'cookie'].forEach(prop => {
    if (getterLooksNonNative(Document.prototype, prop)) hits.push(`Document.prototype.${prop}`);
  });

  try {
    if (getterLooksNonNative(HTMLCanvasElement.prototype, 'toDataURL')) hits.push(`HTMLCanvasElement.prototype.toDataURL`);
    if (getterLooksNonNative(HTMLCanvasElement.prototype, 'getContext')) hits.push(`HTMLCanvasElement.prototype.getContext`);
  } catch (e) {}

  return hits;
}

function permissionQueryLooksNative() {
  if (!navigator.permissions || typeof navigator.permissions.query !== 'function') return false;
  return isFunctionLikelyNative(navigator.permissions.query);
}

function functionToStringTampered() {
  try {
    const current = Function.prototype.toString;
    const bindTampered = !safeToString(Function.prototype.bind).includes('[native code]');
    return current !== NATIVE_REFS.functionToString || bindTampered;
  } catch (error) {
    return false;
  }
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

export function runIntegrityChecks() {
  const patchedGetters = collectPatchedGetterSignals();
  const permissionsNative = permissionQueryLooksNative();
  const toStringTampered = functionToStringTampered();

  const signals = [
    buildSignal(
      'patchedFingerprintGetters',
      'Fingerprint-critical getters are non-native',
      patchedGetters.length > 0,
      patchedGetters
    ),
    buildSignal(
      'permissionsQueryPatched',
      'permissions.query appears non-native',
      navigator.permissions ? !permissionsNative : false,
      {
        permissionsAvailable: !!navigator.permissions,
        nativeSource: safeToString(navigator.permissions && navigator.permissions.query)
      },
      navigator.permissions ? STATES.OK : STATES.UNAVAILABLE
    ),
    buildSignal('functionToStringTamper', 'Function.prototype.toString appears patched', toStringTampered, {
      baselineNative: safeToString(NATIVE_REFS.functionToString),
      current: safeToString(Function.prototype.toString)
    })
  ];

  return {
    signals,
    weakChecks: [
      {
        key: 'permissionsQueryLooksNative',
        label: 'permissions.query appears native',
        ok: navigator.permissions ? permissionsNative : true,
        details: safeToString(navigator.permissions && navigator.permissions.query),
        category: 'integrity',
        state: navigator.permissions ? (permissionsNative ? STATES.OK : STATES.SUSPICIOUS) : STATES.UNAVAILABLE
      }
    ],
    evidence: {
      patchedGetters,
      permissionsNative,
      toStringTampered
    }
  };
}
