export async function getWebRTCSummary(timeoutMs = 2500) {
  if (!window.RTCPeerConnection) {
    return { state: 'unavailable', supported: false, hasHostCandidate: true, candidates: [] };
  }

  return new Promise(resolve => {
    let settled = false;

    const finish = (payload, pc, timer) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        if (pc) pc.close();
      } catch (error) {
        // ignore
      }
      resolve(payload);
    };

    try {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      pc.createDataChannel('probe');
      const candidates = [];

      const timeoutId = setTimeout(() => {
        const hasHost = candidates.some(candidate => / typ host /i.test(candidate));
        finish({ state: 'ok', supported: true, hasHostCandidate: hasHost, candidates, timedOut: true }, pc, null);
      }, timeoutMs);

      pc.onicecandidate = event => {
        if (!event.candidate) {
          const hasHost = candidates.some(candidate => / typ host /i.test(candidate));
          finish({ state: 'ok', supported: true, hasHostCandidate: hasHost, candidates, timedOut: false }, pc, timeoutId);
          return;
        }

        candidates.push(event.candidate.candidate);
      };

      pc.createOffer()
        .then(offer => pc.setLocalDescription(offer))
        .catch(error => {
          finish({
            state: 'error',
            supported: true,
            hasHostCandidate: true,
            candidates: [`offer-error:${String(error)}`],
            timedOut: false
          }, pc, timeoutId);
        });
    } catch (error) {
      finish({ state: 'error', supported: true, hasHostCandidate: true, candidates: [`error:${String(error)}`], timedOut: false }, null, null);
    }
  });
}
