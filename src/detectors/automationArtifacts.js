import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';

export function uaIsChromiumFamily(ua) {
  return /Chrome|Chromium|Edg\//.test(String(ua || '')) && !/OPR\//.test(String(ua || ''));
}

function hasHeadlessToken(value) {
  return /HeadlessChrome|Puppeteer|Playwright|PhantomJS|Selenium/i.test(String(value || ''));
}

function hasHeadlessClientHintsBrand() {
  try {
    const brands = navigator.userAgentData?.brands;
    if (!Array.isArray(brands)) return false;
    return brands.some(entry => /headless/i.test(String(entry?.brand || '')));
  } catch (error) {
    return false;
  }
}

export function listPlaywrightArtifacts() {
  const artifacts = [];
  const keys = ['__playwright__binding__', '__pwInitScripts', '__playwright__', '__pwRunMicrotasks'];
  keys.forEach(key => {
    if (key in window) artifacts.push(`window.${key}`);
  });
  return artifacts;
}

export function listSeleniumArtifacts() {
  const hits = [];
  try {
    const keys = Object.getOwnPropertyNames(window);
    keys.forEach(key => {
      if (key.startsWith('cdc_') || key.startsWith('$cdc_') || key.startsWith('_Selenium_IDE_Recorder')) {
        hits.push(`window.${key}`);
      }
    });
  } catch (error) {
    // ignore
  }

  if (document.$cdc_asdjflasutopfhvcZLmcfl_) hits.push('document.$cdc_asdjflasutopfhvcZLmcfl_');
  if (window.cdc_adoQpoasnfa76pfcZLmcfl) hits.push('window.cdc_adoQpoasnfa76pfcZLmcfl');
  return hits;
}

let cachedCDPStackHookResult = null;

export function detectCDPStackHook() {
  if (cachedCDPStackHookResult !== null) return cachedCDPStackHookResult;

  try {
    let hooked = false;
    const bait = { label: 'cdp-probe' };
    Object.defineProperty(bait, 'stack', {
      configurable: true,
      enumerable: false,
      get() {
        hooked = true;
        return 'cdp-probe-stack';
      }
    });

    // Keep the probe but avoid logging an Error object that looks like a runtime failure in DevTools.
    console.debug('[ab-detector:cdp-probe]', bait);
    cachedCDPStackHookResult = hooked;
    return hooked;
  } catch (err) {
    cachedCDPStackHookResult = false;
    return false;
  }
}

export function collectKeywordArtifacts() {
  const keywords = [/gologin/i, /orbita/i, /maskbrowser/i, /antidetect/i];
  const hits = [];

  try {
    const keys = Object.getOwnPropertyNames(window);
    keys.forEach(key => {
      if (keywords.some(regex => regex.test(key))) hits.push(`window.${key}`);
    });
  } catch (error) {
    // ignore
  }

  try {
    for (let i = 0; i < localStorage.length; i += 1) {
      const key = localStorage.key(i);
      if (key && keywords.some(regex => regex.test(key))) hits.push(`localStorage.${key}`);
    }
  } catch (error) {
    // ignore
  }

  try {
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const key = sessionStorage.key(i);
      if (key && keywords.some(regex => regex.test(key))) hits.push(`sessionStorage.${key}`);
    }
  } catch (error) {
    // ignore
  }

  [navigator.userAgent, navigator.appVersion, navigator.platform, navigator.vendor].forEach(token => {
    if (token && keywords.some(regex => regex.test(token))) hits.push(`uaToken:${token}`);
  });

  return hits;
}

function suspiciousGlobalArtifacts() {
  const patterns = [
    /puppeteer/i,
    /playwright/i,
    /selenium/i,
    /webdriver/i,
    /cdp/i,
    /phantom/i,
    /nightmare/i,
    /automation/i
  ];

  const hits = [];
  const windowKeys = Object.getOwnPropertyNames(window);
  for (let i = 0; i < windowKeys.length; i += 1) {
    const key = windowKeys[i];
    if (patterns.some(regex => regex.test(key))) {
      if (!/^on/.test(key) && !/^webkit/i.test(key) && key.length < 80) {
        hits.push(`window.${key}`);
      }
    }
    if (hits.length > 24) break;
  }

  const docKeys = Object.getOwnPropertyNames(document);
  for (let i = 0; i < docKeys.length; i += 1) {
    const key = docKeys[i];
    if (patterns.some(regex => regex.test(key)) && key.length < 80) {
      hits.push(`document.${key}`);
    }
    if (hits.length > 40) break;
  }

  return hits;
}

function suspiciousNavigatorPrototypeDescriptors() {
  const checks = [
    'webdriver',
    'languages',
    'platform',
    'hardwareConcurrency',
    'deviceMemory',
    'plugins',
    'mimeTypes',
    'userAgent',
    'vendor',
    'appVersion'
  ];
  const hits = [];

  checks.forEach(prop => {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
      if (!descriptor) return;
      if (descriptor.get && !String(Function.prototype.toString.call(descriptor.get)).includes('[native code]')) {
        hits.push(`Navigator.prototype.${prop}:getter-non-native`);
      }
      if (descriptor.set) {
        hits.push(`Navigator.prototype.${prop}:setter-present`);
      }
    } catch (error) {
      // ignore
    }
  });

  return hits;
}

function buildHeadlessAutomationCluster({
  ua,
  workerContext,
  iframeContext,
  webglSummary,
  canvasProbe,
  offscreenProbe,
  cdpStackHook
}) {
  const mainUaHeadless = hasHeadlessToken(ua);
  const workerUaHeadless = workerContext?.state === 'ok' && hasHeadlessToken(workerContext?.userAgent);
  const iframeUaHeadless = iframeContext?.state === 'ok' && hasHeadlessToken(iframeContext?.userAgent);
  const clientHintsHeadless = hasHeadlessClientHintsBrand();
  const webglSoftware = !webglSummary?.renderer || /SwiftShader|llvmpipe/i.test(String(webglSummary.renderer || ''));
  const canvasUnstable = canvasProbe?.state === 'ok' && !canvasProbe?.stable;
  const offscreenSuspicious = offscreenProbe?.state === 'ok'
    && (!offscreenProbe?.stable || !offscreenProbe?.hash);

  const supportFlags = {
    workerUaHeadless: !!workerUaHeadless,
    iframeUaHeadless: !!iframeUaHeadless,
    clientHintsHeadless,
    webglSoftware,
    canvasUnstable,
    offscreenSuspicious,
    cdpStackHook
  };

  const supportCount = Object.values(supportFlags).filter(Boolean).length;
  const suspicious = !!mainUaHeadless && supportCount >= 2;

  return {
    suspicious,
    details: {
      mainUaHeadless,
      supportCount,
      supportFlags
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

export function runAutomationArtifactDetectors({
  ua,
  iframeContext,
  workerContext,
  webglSummary,
  canvasProbe,
  offscreenProbe
}) {
  const playwrightArtifacts = listPlaywrightArtifacts();
  const seleniumArtifacts = listSeleniumArtifacts();
  const keywordArtifacts = collectKeywordArtifacts();
  const suspiciousGlobals = suspiciousGlobalArtifacts();
  const navPrototypeHits = suspiciousNavigatorPrototypeDescriptors();
  const cdpStackHook = detectCDPStackHook();
  const headlessCluster = buildHeadlessAutomationCluster({
    ua,
    workerContext,
    iframeContext,
    webglSummary,
    canvasProbe,
    offscreenProbe,
    cdpStackHook
  });

  const signals = [
    buildSignal('webdriverTrue', 'navigator.webdriver is true', !!navigator.webdriver, navigator.webdriver),
    buildSignal(
      'iframeWebdriverTrue',
      'iframe navigator.webdriver is true',
      iframeContext?.state === 'ok' && !!iframeContext.webdriver,
      iframeContext
    ),
    buildSignal(
      'workerWebdriverTrue',
      'worker navigator.webdriver is true',
      workerContext?.state === 'ok' && !!workerContext.webdriver,
      workerContext
    ),
    buildSignal('playwrightArtifacts', 'Playwright artifacts present', playwrightArtifacts.length > 0, playwrightArtifacts),
    buildSignal('seleniumArtifacts', 'Selenium cdc artifacts present', seleniumArtifacts.length > 0, seleniumArtifacts),
    buildSignal(
      'domAutomationGlobals',
      'domAutomation globals present',
      !!(window.domAutomation || window.domAutomationController),
      {
        domAutomation: !!window.domAutomation,
        domAutomationController: !!window.domAutomationController
      }
    ),
    buildSignal(
      'headlessTokenInUA',
      'Headless automation token in userAgent',
      hasHeadlessToken(ua),
      ua
    ),
    buildSignal(
      'headlessAutomationCluster',
      'Headless automation cluster (UA + supporting signals)',
      headlessCluster.suspicious,
      headlessCluster.details
    ),
    buildSignal('phantomOrNightmare', 'Legacy automation globals present', !!(window.callPhantom || window._phantom || window.phantom || window.__nightmare), {
      callPhantom: !!window.callPhantom,
      _phantom: !!window._phantom,
      phantom: !!window.phantom,
      __nightmare: !!window.__nightmare
    }),
    buildSignal('cdpStackHook', 'CDP stack serialization behavior', cdpStackHook, { cdpStackHook }),
    buildSignal('suspiciousWindowGlobals', 'Suspicious automation-like globals present', suspiciousGlobals.length > 0, suspiciousGlobals),
    buildSignal('gologinKeywordArtifacts', 'GoLogin/Orbita keyword artifacts present', keywordArtifacts.length > 0, keywordArtifacts),
    buildSignal('patchedNavigatorPrototype', 'Navigator prototype descriptors look tampered', navPrototypeHits.length > 0, navPrototypeHits)
  ];

  return {
    signals,
    evidence: {
      playwrightArtifacts,
      seleniumArtifacts,
      keywordArtifacts,
      suspiciousGlobals,
      navPrototypeHits,
      headlessCluster
    }
  };
}
