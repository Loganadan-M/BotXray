import { createDetectorResult, createWeakCheck, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';
import { normalizeLanguageTag } from '../utils/common.js';
import { uaIsChromiumFamily } from './automationArtifacts.js';

function platformMatchesUA(ua, platform) {
  const value = String(platform || '').toLowerCase();
  if (/windows/i.test(ua)) return value.includes('win');
  if (/mac os x|macintosh/i.test(ua)) return value.includes('mac');
  if (/android/i.test(ua)) return value.includes('linux') || value.includes('android');
  if (/linux/i.test(ua)) return value.includes('linux');
  if (/iphone|ipad|ipod/i.test(ua)) {
    return value.includes('iphone') || value.includes('ipad') || value.includes('ipod') || value.includes('mac');
  }
  return true;
}

function chromeObjectConsistency(ua) {
  const chromium = uaIsChromiumFamily(ua);
  if (!chromium) return { ok: true, details: 'non-chromium family' };
  if (!window.chrome) return { ok: false, details: 'window.chrome missing' };
  if (typeof window.chrome !== 'object') return { ok: false, details: 'window.chrome not object' };
  const runtimeLooksValid = !window.chrome.runtime || typeof window.chrome.runtime === 'object';
  if (!runtimeLooksValid) return { ok: false, details: 'window.chrome.runtime has unexpected shape' };
  return { ok: true, details: 'chrome object present' };
}

function pluginMimeConsistency(ua) {
  const chromium = uaIsChromiumFamily(ua);
  const plugins = navigator.plugins;
  const mimeTypes = navigator.mimeTypes;
  const issues = [];

  if (!plugins || typeof plugins.length !== 'number') issues.push('plugins-missing');
  if (!mimeTypes || typeof mimeTypes.length !== 'number') issues.push('mimeTypes-missing');

  if (plugins && typeof plugins.length === 'number' && plugins.length > 0) {
    for (let i = 0; i < Math.min(plugins.length, 4); i += 1) {
      const plugin = plugins[i];
      if (!plugin || typeof plugin.name !== 'string' || typeof plugin.filename !== 'string' || typeof plugin.description !== 'string') {
        issues.push(`plugin-shape-${i}`);
      }
    }
  }

  if (chromium && plugins && plugins.length === 0) issues.push('chromium-zero-plugins');
  if (chromium && mimeTypes && mimeTypes.length === 0) issues.push('chromium-zero-mimetypes');

  return {
    ok: issues.length === 0,
    details: {
      pluginCount: plugins && typeof plugins.length === 'number' ? plugins.length : -1,
      mimeTypeCount: mimeTypes && typeof mimeTypes.length === 'number' ? mimeTypes.length : -1,
      issues
    }
  };
}

function screenConsistencyProbe() {
  const issues = [];
  const sw = screen.width;
  const sh = screen.height;
  const aw = screen.availWidth;
  const ah = screen.availHeight;
  const iw = window.innerWidth;
  const ih = window.innerHeight;
  const ow = window.outerWidth;
  const oh = window.outerHeight;
  const dpr = window.devicePixelRatio;

  if (!(sw > 0 && sh > 0 && iw > 0 && ih > 0)) issues.push('non-positive-dimensions');
  if (aw > sw || ah > sh) issues.push('avail-exceeds-screen');
  if (iw > sw + 4 || ih > sh + 4) issues.push('inner-exceeds-screen');
  if (ow + 2 < iw || oh + 2 < ih) issues.push('outer-smaller-than-inner');
  if (!(dpr > 0 && dpr <= 8)) issues.push('invalid-dpr');

  return {
    ok: issues.length === 0,
    details: { sw, sh, aw, ah, iw, ih, ow, oh, dpr, issues }
  };
}

function touchUaConsistency(ua) {
  const uaMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(ua);
  const touchPoints = Number(navigator.maxTouchPoints || 0);
  const hasTouchEvent = ('ontouchstart' in window) || (navigator.msMaxTouchPoints > 0);
  const issues = [];

  if (uaMobile && touchPoints === 0) issues.push('mobile-ua-no-touchpoints');
  if (touchPoints > 0 && !hasTouchEvent) issues.push('touchpoints-without-touch-api');
  if (!uaMobile && touchPoints > 10) issues.push('desktop-ua-high-touchpoints');

  return { ok: issues.length === 0, details: { uaMobile, touchPoints, hasTouchEvent, issues } };
}

function languageConsistency() {
  const navLang = navigator.language || '';
  const langs = Array.isArray(navigator.languages) ? navigator.languages : [];
  const dateTimeLocale = Intl.DateTimeFormat().resolvedOptions().locale || '';
  let relativeLocale = '';

  try {
    if (typeof Intl.RelativeTimeFormat === 'function') {
      relativeLocale = new Intl.RelativeTimeFormat().resolvedOptions().locale || '';
    }
  } catch (error) {
    relativeLocale = '';
  }

  if (!relativeLocale) relativeLocale = dateTimeLocale;

  const baseNav = normalizeLanguageTag(navLang);
  const baseIntl = normalizeLanguageTag(dateTimeLocale);
  const baseRel = normalizeLanguageTag(relativeLocale);

  const listHasNavLanguage = langs.includes(navLang) || langs.some(lang => normalizeLanguageTag(lang) === baseNav);
  const consistent = !!baseNav && baseNav === baseIntl && baseIntl === baseRel;

  return {
    navLang,
    dateTimeLocale,
    relativeLocale,
    listHasNavLanguage,
    consistent,
    languages: langs
  };
}

function timezoneLocaleConsistency() {
  try {
    const options = Intl.DateTimeFormat().resolvedOptions();
    const timezone = options.timeZone || '';
    const locale = options.locale || '';
    const offsetMinutes = new Date().getTimezoneOffset();

    const suspicious = !timezone || !locale;
    return {
      ok: !suspicious,
      details: {
        timezone,
        locale,
        offsetMinutes
      }
    };
  } catch (error) {
    return { ok: true, details: { unavailable: true, error: String(error) } };
  }
}

async function notificationPermissionConsistency() {
  if (!navigator.permissions || typeof navigator.permissions.query !== 'function') {
    return { ok: true, state: STATES.UNAVAILABLE, details: 'permissions api unavailable' };
  }

  if (typeof Notification === 'undefined') {
    return { ok: true, state: STATES.UNAVAILABLE, details: 'Notification API unavailable' };
  }

  try {
    const status = await navigator.permissions.query({ name: 'notifications' });
    const navState = Notification.permission;
    const permState = status && status.state ? status.state : 'unknown';
    const map = { default: 'prompt' };
    const expected = map[navState] || navState;
    return {
      ok: expected === permState,
      state: STATES.OK,
      details: {
        notificationPermission: navState,
        permissionsQueryState: permState,
        expected
      }
    };
  } catch (error) {
    return { ok: true, state: STATES.UNAVAILABLE, details: { error: String(error) } };
  }
}

function compareCrossContext(mainContext, workerContext, iframeContext) {
  const mismatches = [];

  if (workerContext?.state === 'ok') {
    if (String(mainContext.platform || '') !== String(workerContext.platform || '')) {
      mismatches.push('main-worker-platform');
    }

    if (!!mainContext.webdriver !== !!workerContext.webdriver) {
      mismatches.push('main-worker-webdriver');
    }

    if (String(mainContext.language || '') !== String(workerContext.language || '')) {
      mismatches.push('main-worker-language');
    }

    if (String(mainContext.timezone || '') !== String(workerContext.timezone || '')) {
      mismatches.push('main-worker-timezone');
    }
  }

  if (iframeContext?.state === 'ok') {
    if (String(mainContext.platform || '') !== String(iframeContext.platform || '')) {
      mismatches.push('main-iframe-platform');
    }

    if (!!mainContext.webdriver !== !!iframeContext.webdriver) {
      mismatches.push('main-iframe-webdriver');
    }
  }

  return {
    ok: mismatches.length === 0,
    mismatches,
    workerState: workerContext?.state || 'unavailable',
    iframeState: iframeContext?.state || 'unavailable'
  };
}

function webglPlatformConsistency(ua, webglSummary) {
  const renderer = String(webglSummary?.renderer || '').toLowerCase();
  if (!renderer) return { ok: true, details: { unavailable: true } };

  const uaMac = /Macintosh|Mac OS X/i.test(ua);
  const uaWindows = /Windows/i.test(ua);
  const suspicious = (uaMac && renderer.includes('direct3d')) || (uaWindows && renderer.includes('metal'));

  return {
    ok: !suspicious,
    details: {
      ua,
      renderer,
      uaMac,
      uaWindows
    }
  };
}

function mobileDesktopTraitMismatch(ua) {
  const uaMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(ua);
  const hasTouch = Number(navigator.maxTouchPoints || 0) > 0;
  const issues = [];

  if (uaMobile && window.innerWidth > 1600) issues.push('mobile-ua-large-viewport');
  if (!uaMobile && hasTouch && window.innerWidth >= 1400 && window.outerHeight > 900) {
    issues.push('desktop-ua-with-mobile-traits');
  }

  return {
    ok: issues.length === 0,
    details: {
      uaMobile,
      hasTouch,
      innerWidth: window.innerWidth,
      outerHeight: window.outerHeight,
      issues
    }
  };
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

export async function runConsistencyChecks({ ua, clientHints, mainContext, workerContext, iframeContext, webglSummary }) {
  const platformUaMatch = platformMatchesUA(ua, navigator.platform);
  const chromeConsistency = chromeObjectConsistency(ua);
  const pluginConsistency = pluginMimeConsistency(ua);
  const screenConsistency = screenConsistencyProbe();
  const touchConsistency = touchUaConsistency(ua);
  const langConsistency = languageConsistency();
  const timezoneConsistency = timezoneLocaleConsistency();
  const permissionConsistency = await notificationPermissionConsistency();
  const crossContext = compareCrossContext(mainContext, workerContext, iframeContext);
  const webglConsistency = webglPlatformConsistency(ua, webglSummary);
  const traitMismatch = mobileDesktopTraitMismatch(ua);

  const dpr = window.devicePixelRatio;
  const dprImplausible = !(typeof dpr === 'number' && dpr > 0 && dpr <= 8);

  const signals = [
    buildSignal('workerMismatch', 'Cross-context navigator mismatch', !crossContext.ok, crossContext, crossContext.workerState === 'ok' ? STATES.OK : STATES.UNAVAILABLE),
    buildSignal('platformMismatch', 'UA platform mismatches navigator.platform', !platformUaMatch, { ua, platform: navigator.platform }),
    buildSignal('clientHintsMismatch', 'UA-CH platform mismatches navigator.platform', !!clientHints && !clientHints.ok, clientHints?.details || clientHints, clientHints?.state === 'unavailable' ? STATES.UNAVAILABLE : STATES.OK),
    buildSignal('webglPlatformMismatch', 'WebGL renderer family mismatches UA platform', !webglConsistency.ok, webglConsistency.details),
    buildSignal('languageInconsistent', 'navigator.language inconsistent with Intl locale', !langConsistency.consistent || !langConsistency.listHasNavLanguage, langConsistency),
    buildSignal('timezoneLocaleMismatch', 'Timezone/locale signals look inconsistent', !timezoneConsistency.ok, timezoneConsistency.details, timezoneConsistency.details?.unavailable ? STATES.UNAVAILABLE : STATES.OK),
    buildSignal('notificationPermissionMismatch', 'Notification permission mismatch', !permissionConsistency.ok, permissionConsistency.details, permissionConsistency.state),
    buildSignal('pluginMimeInconsistent', 'Plugins/mimeTypes inconsistent', !pluginConsistency.ok, pluginConsistency.details),
    buildSignal('screenGeometryInconsistent', 'Screen/window geometry inconsistent', !screenConsistency.ok, screenConsistency.details),
    buildSignal('touchUaInconsistent', 'Touch capabilities inconsistent with UA', !touchConsistency.ok, touchConsistency.details),
    buildSignal('chromeObjectInconsistent', 'Chrome object shape inconsistent', !chromeConsistency.ok, chromeConsistency.details),
    buildSignal('devicePixelRatioImplausible', 'devicePixelRatio outside plausible bounds', dprImplausible, { dpr }),
    buildSignal('mobileDesktopTraitMismatch', 'UA family mismatches desktop/mobile traits', !traitMismatch.ok, traitMismatch.details)
  ];

  const weakChecks = [
    createWeakCheck({ key: 'workerNavigatorConsistent', label: 'Main/worker/iframe navigator consistency', ok: crossContext.ok, details: crossContext }),
    createWeakCheck({ key: 'platformMatchesUA', label: 'navigator.platform matches UA family', ok: platformUaMatch, details: { ua, platform: navigator.platform } }),
    createWeakCheck({ key: 'clientHintsPlatformConsistent', label: 'UA-CH platform consistency', ok: !clientHints || clientHints.ok, details: clientHints?.details || clientHints, state: clientHints?.state === 'unavailable' ? STATES.UNAVAILABLE : STATES.OK }),
    createWeakCheck({ key: 'languagesConsistent', label: 'Language consistency across navigator/Intl', ok: langConsistency.consistent && langConsistency.listHasNavLanguage, details: langConsistency }),
    createWeakCheck({ key: 'timezoneLocaleConsistent', label: 'Timezone + locale signal consistency', ok: timezoneConsistency.ok, details: timezoneConsistency.details, state: timezoneConsistency.details?.unavailable ? STATES.UNAVAILABLE : STATES.OK }),
    createWeakCheck({ key: 'notificationPermissionConsistent', label: 'Notification permission consistency', ok: permissionConsistency.ok, details: permissionConsistency.details, state: permissionConsistency.state }),
    createWeakCheck({ key: 'pluginMimeConsistent', label: 'Plugins/mimeTypes consistency', ok: pluginConsistency.ok, details: pluginConsistency.details }),
    createWeakCheck({ key: 'screenGeometryConsistent', label: 'Screen/window geometry consistency', ok: screenConsistency.ok, details: screenConsistency.details }),
    createWeakCheck({ key: 'touchUaConsistent', label: 'Touch capability consistency', ok: touchConsistency.ok, details: touchConsistency.details }),
    createWeakCheck({ key: 'chromeObjectConsistent', label: 'Chrome object consistency', ok: chromeConsistency.ok, details: chromeConsistency.details })
  ];

  return {
    signals,
    weakChecks,
    evidence: {
      crossContext,
      platformUaMatch,
      langConsistency,
      permissionConsistency,
      pluginConsistency,
      screenConsistency,
      touchConsistency,
      timezoneConsistency,
      webglConsistency,
      traitMismatch
    }
  };
}
