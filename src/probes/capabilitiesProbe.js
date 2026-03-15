export async function getMediaDevicesSummary() {
  try {
    if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== 'function') {
      return { state: 'unavailable', supported: false };
    }

    const devices = await navigator.mediaDevices.enumerateDevices();
    const counts = devices.reduce((acc, device) => {
      const key = device.kind || 'unknown';
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});

    return {
      state: 'ok',
      supported: true,
      total: devices.length,
      counts
    };
  } catch (error) {
    return { state: 'error', supported: true, error: String(error) };
  }
}

export function getSpeechVoicesSummary() {
  try {
    if (!window.speechSynthesis || typeof speechSynthesis.getVoices !== 'function') {
      return { state: 'unavailable', supported: false, count: 0 };
    }

    const voices = speechSynthesis.getVoices() || [];
    return {
      state: 'ok',
      supported: true,
      count: voices.length,
      sample: voices.slice(0, 8).map(v => ({ name: v.name, lang: v.lang, localService: v.localService }))
    };
  } catch (error) {
    return { state: 'error', supported: true, count: 0, error: String(error) };
  }
}

export function getConnectionSummary() {
  try {
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!connection) {
      return { state: 'unavailable', supported: false };
    }

    return {
      state: 'ok',
      supported: true,
      effectiveType: connection.effectiveType || '',
      downlink: connection.downlink,
      rtt: connection.rtt,
      saveData: !!connection.saveData
    };
  } catch (error) {
    return { state: 'error', supported: true, error: String(error) };
  }
}

export async function getBatterySummary() {
  try {
    if (typeof navigator.getBattery !== 'function') {
      return { state: 'unavailable', supported: false };
    }

    const battery = await navigator.getBattery();
    return {
      state: 'ok',
      supported: true,
      charging: !!battery.charging,
      chargingTime: battery.chargingTime,
      dischargingTime: battery.dischargingTime,
      level: battery.level
    };
  } catch (error) {
    return { state: 'error', supported: true, error: String(error) };
  }
}

export function getMediaCapabilitiesSummary() {
  try {
    if (!navigator.mediaCapabilities) {
      return { state: 'unavailable', supported: false };
    }

    return {
      state: 'ok',
      supported: true,
      hasDecodingInfo: typeof navigator.mediaCapabilities.decodingInfo === 'function',
      hasEncodingInfo: typeof navigator.mediaCapabilities.encodingInfo === 'function'
    };
  } catch (error) {
    return { state: 'error', supported: true, error: String(error) };
  }
}
