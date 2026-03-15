import { safeToString } from './common.js';

const capture = {
  functionToString: Function.prototype.toString,
  objectGetOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
  permissionsQuery: typeof navigator !== 'undefined' && navigator.permissions
    ? navigator.permissions.query
    : null,
  performanceNow: typeof performance !== 'undefined' ? performance.now.bind(performance) : Date.now,
  dateTimeFormat: Intl.DateTimeFormat,
  relativeTimeFormat: Intl.RelativeTimeFormat
};

export const NATIVE_REFS = Object.freeze(capture);

export function nativeSourceOf(fn) {
  try {
    if (typeof fn !== 'function') return 'unavailable';
    return NATIVE_REFS.functionToString.call(fn);
  } catch (error) {
    return safeToString(fn);
  }
}

export function isFunctionLikelyNative(fn) {
  const src = nativeSourceOf(fn);
  return src.includes('[native code]');
}
