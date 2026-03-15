function uaIsChromiumFamily(ua) {
  return /Chrome|Chromium|Edg\//.test(ua) && !/OPR\//.test(ua);
}

export async function getClientHintsData() {
  if (!navigator.userAgentData || typeof navigator.userAgentData.getHighEntropyValues !== 'function') {
    return { state: 'unavailable', ok: true, details: { unavailable: true } };
  }

  try {
    const high = await navigator.userAgentData.getHighEntropyValues([
      'platform',
      'architecture',
      'model',
      'platformVersion',
      'fullVersionList',
      'bitness'
    ]);

    const brands = Array.isArray(navigator.userAgentData.brands) ? navigator.userAgentData.brands : [];
    const mobile = !!navigator.userAgentData.mobile;
    const hasChromiumBrand = brands.some(entry => /Chrom|Google Chrome|Microsoft Edge/i.test(String(entry.brand || '')));
    const userAgent = navigator.userAgent || '';
    const chPlatform = String(high.platform || '').toLowerCase();
    const navPlatform = String(navigator.platform || '').toLowerCase();
    const platformOk = !chPlatform || navPlatform.includes(chPlatform) || chPlatform.includes(navPlatform);
    const brandOk = !uaIsChromiumFamily(userAgent) || hasChromiumBrand;

    return {
      state: 'ok',
      ok: platformOk && brandOk,
      details: {
        chPlatform,
        navPlatform,
        architecture: high.architecture || '',
        model: high.model || '',
        platformVersion: high.platformVersion || '',
        bitness: high.bitness || '',
        brands,
        fullVersionList: high.fullVersionList || [],
        mobile,
        platformOk,
        brandOk
      }
    };
  } catch (error) {
    return { state: 'error', ok: true, details: { error: String(error) } };
  }
}
