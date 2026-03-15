import { toBackendPayload } from './serializer.js';

/**
 * Optional backend submission helper.
 * Safe to keep unused in client-only deployments.
 */
export async function sendDetectionResult(url, result, options = {}) {
  const {
    retries = 1,
    timeoutMs = 5000,
    headers = {}
  } = options;

  const payload = toBackendPayload(result);

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...headers
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
        keepalive: true
      });

      clearTimeout(timer);

      if (!response.ok) {
        throw new Error(`submission-failed:${response.status}`);
      }

      return {
        ok: true,
        status: response.status,
        attempt
      };
    } catch (error) {
      clearTimeout(timer);
      if (attempt >= retries) {
        return {
          ok: false,
          error: String(error),
          attempt
        };
      }
    }
  }

  return {
    ok: false,
    error: 'submission-failed-unknown'
  };
}
