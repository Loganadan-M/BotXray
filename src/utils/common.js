export function bool(value) {
  return !!value;
}

export function safeToString(fn) {
  try {
    if (typeof fn !== 'function') return 'unavailable';
    return Function.prototype.toString.call(fn);
  } catch (error) {
    return 'unavailable';
  }
}

export function hashString(input) {
  let hash = 2166136261;
  const value = String(input);
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16);
}

export function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

export function mean(values) {
  if (!Array.isArray(values) || values.length === 0) return 0;
  return values.reduce((acc, value) => acc + value, 0) / values.length;
}

export function stdDev(values) {
  if (!Array.isArray(values) || values.length < 2) return 0;
  const avg = mean(values);
  const variance = mean(values.map(value => (value - avg) ** 2));
  return Math.sqrt(variance);
}

export function normalizeLanguageTag(tag) {
  if (!tag || typeof tag !== 'string') return '';
  return tag.toLowerCase().split('-')[0];
}

export function nowIso() {
  return new Date().toISOString();
}

export function createRunId() {
  try {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
      return globalThis.crypto.randomUUID();
    }
  } catch (error) {
    // ignore
  }

  const suffix = Math.random().toString(36).slice(2, 10);
  return `run-${Date.now()}-${suffix}`;
}

export function round(value, decimals = 2) {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

export function deepFreeze(obj) {
  if (!obj || typeof obj !== 'object' || Object.isFrozen(obj)) return obj;
  Object.freeze(obj);
  Object.getOwnPropertyNames(obj).forEach(key => {
    const value = obj[key];
    if (value && typeof value === 'object') deepFreeze(value);
  });
  return obj;
}

export function tryOrFallback(fn, fallback) {
  try {
    return fn();
  } catch (error) {
    return fallback;
  }
}

export function safeJsonParse(value, fallback = null) {
  try {
    return JSON.parse(value);
  } catch (error) {
    return fallback;
  }
}
