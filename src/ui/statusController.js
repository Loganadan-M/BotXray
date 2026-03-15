export function createStatusController() {
  let loadingTimer = null;
  let loadingStartedAt = 0;
  let loading = false;

  function setLoadingMeter(progress) {
    const fill = document.getElementById('loadingMeterFill');
    if (!fill) return;
    fill.style.width = `${Math.max(0, Math.min(progress, 100)).toFixed(0)}%`;
  }

  function setLoading(isLoading) {
    const runButton = document.getElementById('runDetectionBtn');
    const status = document.getElementById('detectionStatus');

    if (!runButton || !status) return;

    if (isLoading) {
      loading = true;
      loadingStartedAt = performance.now();
      runButton.disabled = true;
      runButton.textContent = 'Analyzing...';
      status.className = 'status loading';
      status.textContent = 'Analyzing environment (0.0s)';
      setLoadingMeter(8);

      if (loadingTimer) clearInterval(loadingTimer);
      loadingTimer = setInterval(() => {
        const elapsedRaw = performance.now() - loadingStartedAt;
        const elapsed = (elapsedRaw / 1000).toFixed(1);
        const progress = Math.min(94, 12 + (elapsedRaw / 7000) * 82);
        status.textContent = `Analyzing environment (${elapsed}s)`;
        setLoadingMeter(progress);
      }, 120);

      return;
    }

    loading = false;
    runButton.disabled = false;
    runButton.textContent = 'Run Full Detection';
    status.className = 'status ready';
    status.textContent = 'Ready';
    setLoadingMeter(100);
    setTimeout(() => setLoadingMeter(0), 260);

    if (loadingTimer) {
      clearInterval(loadingTimer);
      loadingTimer = null;
    }
  }

  return {
    setLoading,
    isLoading() {
      return loading;
    }
  };
}
