# Anti-Bot Detector v3

## Overview
`anti_bot_detector.html` now runs a modular detector engine from `src/main.js`.

Result payloads are versioned and backend-ready:
- `schemaVersion`: result schema version
- `detectorVersion`: detector runtime version
- `runId`: unique collector execution id
- `checksum`: stable payload checksum for integrity and dedupe

## Detector Categories
- `automation`: direct automation artifacts (`webdriver`, Playwright/Selenium globals, domAutomation, legacy Phantom, CDP stack behavior).
- `integrity`: prototype/getter tampering and native function patch detection.
- `consistency`: UA/platform/client-hints/language/timezone/permissions/screen/touch/chrome object coherence.
- `fingerprint`: canvas/offscreen/text-metrics/client-rect/audio stability checks.
- `environment`: hardware plausibility, plugin profile, WebRTC summary, media capability mismatch.
- `behavior`: summarized interaction telemetry and synthetic-pattern heuristics.

## Strong vs Weak
Strong (high-confidence) detectors include:
- `webdriverTrue`, `iframeWebdriverTrue`, `workerWebdriverTrue`
- `playwrightArtifacts`, `seleniumArtifacts`, `domAutomationGlobals`
- `headlessAutomationCluster` (headless UA corroborated by probe cluster)
- `patchedNavigatorPrototype`, `patchedFingerprintGetters`

Weak / contextual detectors include:
- `zeroPluginsChromium`, `webrtcNoHostCandidate`, `languageInconsistent`, `noHumanInteraction`
- geometry and touch consistency mismatches

The engine avoids over-blocking by:
- category-weighted scoring
- consistency-based dampening when many weak checks pass
- cluster-based escalation for corroborated suspicious patterns
- explicit `unavailable` state (not auto-treated as suspicious)

Additional scripted-invocation hardening:
- stack-based invocation classification (user-event vs evaluated/injected call path)
- cluster escalation when scripted invocation corroborates unstable graphics probes

## False Positive Risks
Common legitimate cases:
- privacy-hardened browsers with reduced plugins/WebRTC
- disabled permissions or blocked workers by policy/CSP
- delayed speech voices loading
- device-specific touch/viewport combinations

Mitigations already included:
- weak signals have lower weights
- unavailable APIs are separated from suspicious signals
- no single weak signal can force a block

## File Map
- `src/main.js`: orchestration pipeline
- `src/config/detectorConfig.js`: config/thresholds/enable flags
- `src/detectors/*.js`: detector modules by domain
- `src/probes/*.js`: probe collectors
- `src/scoring/riskEngine.js`: scoring, escalation, action mapping
- `src/reporting/*.js`: formatting, serialization, optional sender
- `src/ui/*.js`: rendering and loading status handling

## How To Add A Detector
1. Add rule metadata in `src/scoring/rules.js` (`weight`, `confidence`, `category`, `severity`).
2. Implement detector logic in the appropriate `src/detectors/*.js` module.
3. Return normalized detector objects (`key`, `label`, `value`, `state`, `evidence`, etc.).
4. Include the module output in `src/main.js` aggregation.
5. Add fixture coverage in `fixtures/detector_fixtures.json`.

## Tuning Weights And Actions
Tune in `src/config/detectorConfig.js`:
- `scoring.categoryWeights`
- `scoring.criticalSignalKeys`
- `scoring.consistencyReward`
- `scoring.actionMapping`

## Local Run
Use any static file server rooted at `discoverCars/`.

Example:
```bash
cd discoverCars
python3 -m http.server 8000
# open http://127.0.0.1:8000/anti_bot_detector.html
```

## Backend Integration
Use:
- `serializeDetectionResult(result)` for storage/logging
- `sendDetectionResult(url, result, opts)` for optional network submission

No backend dependency is required for local client-only operation.
