# Detector Catalog

## Automation
- `webdriverTrue`: direct `navigator.webdriver` signal (strong).
- `iframeWebdriverTrue`: iframe webdriver leakage (strong).
- `workerWebdriverTrue`: worker webdriver leakage (strong).
- `playwrightArtifacts`: Playwright globals in `window` (strong).
- `seleniumArtifacts`: Selenium CDC/global markers (strong).
- `domAutomationGlobals`: Chrome automation globals (strong).
- `headlessTokenInUA`: explicit headless tokens in UA (strong).
- `headlessAutomationCluster`: headless token plus corroborating probe cluster (strong).
- `phantomOrNightmare`: legacy automation globals (strong).
- `cdpStackHook`: suspicious stack getter behavior (strong/contextual).
- `suspiciousWindowGlobals`: automation-like naming artifacts (weak/contextual).

## Integrity
- `patchedFingerprintGetters`: non-native getters on fingerprint-critical fields.
- `patchedNavigatorPrototype`: suspicious navigator prototype descriptors.
- `permissionsQueryPatched`: non-native permissions query function.
- `functionToStringTamper`: tampered `Function.prototype.toString`.

## Consistency
- `workerMismatch`: main/worker/iframe navigator mismatch.
- `platformMismatch`: UA vs navigator.platform mismatch.
- `clientHintsMismatch`: UA-CH vs platform/brands mismatch.
- `webglPlatformMismatch`: renderer family vs claimed OS mismatch.
- `languageInconsistent`: navigator vs Intl locale mismatch.
- `timezoneLocaleMismatch`: timezone/locale coherence issue.
- `notificationPermissionMismatch`: Notification permission inconsistency.
- `pluginMimeInconsistent`: plugin/mime shape inconsistency.
- `screenGeometryInconsistent`: viewport/screen geometry mismatch.
- `touchUaInconsistent`: touch capability mismatch with UA family.
- `chromeObjectInconsistent`: Chromium object shape mismatch.
- `devicePixelRatioImplausible`: implausible DPR range.
- `mobileDesktopTraitMismatch`: desktop/mobile trait contradiction.

## Fingerprint
- `canvasOutputUnstable`: unstable canvas hash.
- `offscreenCanvasMismatch`: suspicious offscreen/main fingerprint relation.
- `clientRectsUnstable`: unstable rect measurements.
- `audioOutputUnstable`: unstable offline-audio output.
- `textMetricsUnstable`: unstable text measurement output.
- `suspiciousFontProfile`: too little font differentiation.

## Environment
- `suspiciousDeviceMemory`: implausible device memory value.
- `suspiciousHardwareConcurrency`: implausible CPU core count.
- `swiftShaderOrNoWebGL`: software/no renderer.
- `zeroPluginsChromium`: Chromium profile with zero plugins.
- `webrtcNoHostCandidate`: no host ICE candidate when supported.
- `mediaCapabilitiesMismatch`: media capability support mismatch.

## Behavior (summarized telemetry only)
- `noHumanInteraction`: no input after dwell threshold.
- `lowInteractionEntropy`: very low-diversity event patterns.
- `suspiciousMousePattern`: linear, low-acceleration movement.
- `suspiciousClickCadence`: unnaturally periodic click intervals.
- `suspiciousScrollBurst`: unnaturally bursty wheel cadence.
- `programmaticNoActivation`: scripted detector invocation with no user activation.
- `scriptedInvocationStack`: invocation stack indicates script-evaluated call path.
