function localeFromIntl() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().locale;
  } catch (error) {
    return '';
  }
}

function timezoneFromIntl() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  } catch (error) {
    return '';
  }
}

export function getMainContextData() {
  return {
    state: 'ok',
    platform: navigator.platform || '',
    userAgent: navigator.userAgent || '',
    webdriver: !!navigator.webdriver,
    languages: Array.isArray(navigator.languages) ? navigator.languages.slice() : [],
    language: navigator.language || '',
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    maxTouchPoints: navigator.maxTouchPoints,
    locale: localeFromIntl(),
    timezone: timezoneFromIntl()
  };
}

export async function getWorkerContextData(timeoutMs = 1200) {
  if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined') {
    return { state: 'unavailable', reason: 'worker-unsupported' };
  }

  return new Promise(resolve => {
    let finished = false;

    const done = (payload, url, worker, timer) => {
      if (finished) return;
      finished = true;
      if (timer) clearTimeout(timer);
      try {
        if (url) URL.revokeObjectURL(url);
      } catch (error) {
        // ignore
      }
      try {
        if (worker) worker.terminate();
      } catch (error) {
        // ignore
      }
      resolve(payload);
    };

    const workerCode = `
      function localeFromIntl() {
        try { return Intl.DateTimeFormat().resolvedOptions().locale; } catch (e) { return ''; }
      }
      function timezoneFromIntl() {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; }
      }
      postMessage({
        state: 'ok',
        platform: self.navigator.platform || '',
        userAgent: self.navigator.userAgent || '',
        webdriver: !!self.navigator.webdriver,
        languages: Array.isArray(self.navigator.languages) ? self.navigator.languages : [],
        language: self.navigator.language || '',
        hardwareConcurrency: self.navigator.hardwareConcurrency,
        deviceMemory: self.navigator.deviceMemory,
        maxTouchPoints: self.navigator.maxTouchPoints,
        locale: localeFromIntl(),
        timezone: timezoneFromIntl()
      });
    `;

    const blob = new Blob([workerCode], { type: 'application/javascript' });
    const workerUrl = URL.createObjectURL(blob);
    const worker = new Worker(workerUrl);

    const timer = setTimeout(() => {
      done({ state: 'error', reason: 'worker-timeout' }, workerUrl, worker, null);
    }, timeoutMs);

    worker.onmessage = event => {
      done(event.data, workerUrl, worker, timer);
    };

    worker.onerror = error => {
      done({ state: 'error', reason: `worker-error:${String(error.message || error.type || error)}` }, workerUrl, worker, timer);
    };
  });
}

export async function getIframeContextData() {
  return new Promise(resolve => {
    const iframe = document.createElement('iframe');
    try {
      iframe.style.display = 'none';
      iframe.sandbox = 'allow-same-origin'; // Security hardening
      document.body.appendChild(iframe);

      const contentWindow = iframe.contentWindow;
      if (!contentWindow || !contentWindow.navigator) {
        resolve({ state: 'unavailable', reason: 'iframe-no-window' });
      } else {
        const nav = contentWindow.navigator;
        resolve({
          state: 'ok',
          platform: nav.platform || '',
          userAgent: nav.userAgent || '',
          webdriver: !!nav.webdriver,
          language: nav.language || '',
          languages: Array.isArray(nav.languages) ? nav.languages : [],
          hardwareConcurrency: nav.hardwareConcurrency,
          deviceMemory: nav.deviceMemory,
          maxTouchPoints: nav.maxTouchPoints
        });
      }
    } catch (error) {
      resolve({ state: 'error', reason: String(error) });
    } finally {
      if (iframe && iframe.parentNode) {
        document.body.removeChild(iframe);
      }
    }
  });
}
