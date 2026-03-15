/**
 * Advanced Behavior Tracking Module
 * Monitors and analyzes user interactions to detect bot-like patterns
 *
 * Tracks:
 * - Mouse movement patterns (velocity, acceleration, curves)
 * - Click patterns and timing
 * - Scroll behavior and velocity
 * - Form interaction patterns
 * - Keystroke dynamics
 * - Focus/blur patterns
 */

import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { resolveRule } from '../scoring/rules.js';

class AdvancedBehaviorTracker {
  constructor() {
    this.mouseEvents = [];
    this.clickEvents = [];
    this.scrollEvents = [];
    this.keyboardEvents = [];
    this.focusEvents = [];
    this.formInteractions = [];
    this.startTime = performance.now();
    this.lastMousePos = { x: 0, y: 0, time: 0 };
    this.isTracking = false;
    this.suspiciousPatterns = [];
  }

  start() {
    if (this.isTracking) return;
    this.isTracking = true;
    this.startTime = performance.now();

    // Track mouse movement
    document.addEventListener('mousemove', (e) => this.onMouseMove(e), true);

    // Track clicks
    document.addEventListener('click', (e) => this.onClick(e), true);
    document.addEventListener('mousedown', (e) => this.onMouseDown(e), true);

    // Track scrolling
    document.addEventListener('scroll', () => this.onScroll(), true);

    // Track keyboard
    document.addEventListener('keydown', (e) => this.onKeyDown(e), true);
    document.addEventListener('keyup', (e) => this.onKeyUp(e), true);

    // Track focus
    document.addEventListener('focus', (e) => this.onFocus(e), true);
    document.addEventListener('blur', (e) => this.onBlur(e), true);

    // Track form inputs
    document.addEventListener('input', (e) => this.onInput(e), true);
  }

  onMouseMove(event) {
    const now = performance.now();
    const { clientX, clientY } = event;

    if (this.lastMousePos.time === 0) {
      this.lastMousePos = { x: clientX, y: clientY, time: now };
      return;
    }

    const dx = clientX - this.lastMousePos.x;
    const dy = clientY - this.lastMousePos.y;
    const dt = Math.max(now - this.lastMousePos.time, 1);
    const distance = Math.sqrt(dx * dx + dy * dy);
    const velocity = distance / dt;

    this.mouseEvents.push({
      x: clientX,
      y: clientY,
      time: now,
      velocity: velocity,
      dx: dx,
      dy: dy,
      distance: distance
    });

    this.lastMousePos = { x: clientX, y: clientY, time: now };
  }

  onClick(event) {
    const now = performance.now();
    this.clickEvents.push({
      x: event.clientX,
      y: event.clientY,
      time: now,
      target: event.target?.tagName || 'unknown',
      elapsed: now - this.startTime
    });
  }

  onMouseDown(event) {
    // Track mouse down time for click duration analysis
    if (!this._mouseDownTime) {
      this._mouseDownTime = performance.now();
    }
  }

  onScroll() {
    const now = performance.now();
    this.scrollEvents.push({
      scrollY: window.scrollY,
      scrollX: window.scrollX,
      time: now,
      elapsed: now - this.startTime
    });
  }

  onKeyDown(event) {
    const now = performance.now();
    this.keyboardEvents.push({
      key: event.key,
      type: 'keydown',
      time: now,
      elapsed: now - this.startTime
    });
  }

  onKeyUp(event) {
    const now = performance.now();
    this.keyboardEvents.push({
      key: event.key,
      type: 'keyup',
      time: now,
      elapsed: now - this.startTime
    });
  }

  onFocus(event) {
    const now = performance.now();
    this.focusEvents.push({
      type: 'focus',
      target: event.target?.tagName || 'unknown',
      time: now,
      elapsed: now - this.startTime
    });
  }

  onBlur(event) {
    const now = performance.now();
    this.focusEvents.push({
      type: 'blur',
      target: event.target?.tagName || 'unknown',
      time: now,
      elapsed: now - this.startTime
    });
  }

  onInput(event) {
    const now = performance.now();
    this.formInteractions.push({
      value: event.target?.value?.length || 0,
      type: event.target?.type || 'unknown',
      time: now,
      elapsed: now - this.startTime,
      targetName: event.target?.name || 'unknown'
    });
  }

  analyzeMouseMovement() {
    if (this.mouseEvents.length < 10) {
      return { signals: [], evidence: { reason: 'insufficient-mouse-events' } };
    }

    const signals = [];
    const velocities = this.mouseEvents.map(e => e.velocity);
    const distances = this.mouseEvents.map(e => e.distance);

    // Calculate statistics
    const avgVelocity = velocities.reduce((a, b) => a + b, 0) / velocities.length;
    const stdVelocity = Math.sqrt(
      velocities.reduce((sum, v) => sum + Math.pow(v - avgVelocity, 2), 0) / velocities.length
    );
    const avgDistance = distances.reduce((a, b) => a + b, 0) / distances.length;

    const evidence = {
      mouseEventCount: this.mouseEvents.length,
      avgVelocity: Math.round(avgVelocity * 100) / 100,
      stdVelocity: Math.round(stdVelocity * 100) / 100,
      avgDistance: Math.round(avgDistance * 100) / 100,
      minVelocity: Math.min(...velocities),
      maxVelocity: Math.max(...velocities)
    };

    // Detect suspicious patterns
    // NOTE: Thresholds are VERY HIGH to avoid false positives on normal users

    // 1. Suspiciously consistent velocity (bots move at constant speed)
    // Require EXTREME consistency (std < 5% of mean) and substantial mouse movement
    if (stdVelocity < avgVelocity * 0.05 && this.mouseEvents.length >= 150) {
      signals.push({
        key: 'mouseVelocityTooConsistent',
        label: 'Mouse velocity suspiciously consistent',
        value: true,
        confidence: 72,
        weight: 5
      });
    }

    // 2. Zero velocity between events (instant teleportation)
    // Require extremely high rate of zero-velocity events (>60%)
    const zeroVelocityEvents = velocities.filter(v => v === 0).length;
    if (zeroVelocityEvents > velocities.length * 0.6 && this.mouseEvents.length >= 150) {
      signals.push({
        key: 'suspiciousMouseTeleportation',
        label: 'Mouse appears to teleport between positions',
        value: true,
        confidence: 68,
        weight: 4
      });
    }

    // 3. Perfectly straight lines (linear movement)
    // Require extremely high linearity (>80%) with very long movement
    const linearMovements = this.countLinearSegments();
    if (linearMovements > this.mouseEvents.length * 0.8 && this.mouseEvents.length >= 200) {
      signals.push({
        key: 'suspiciouslyLinearMousePath',
        label: 'Mouse movements are suspiciously linear',
        value: true,
        confidence: 65,
        weight: 4
      });
    }

    // 4. No micro-corrections (human natural movement)
    // DISABLED by default - require extremes: very few direction changes over very long movement
    const directions = this.analyzeMovementDirections();
    if (directions.directionChanges < 5 && this.mouseEvents.length >= 300) {
      signals.push({
        key: 'noMouseMicroCorrections',
        label: 'Mouse movement lacks natural micro-corrections',
        value: true,
        confidence: 60,
        weight: 3
      });
    }

    return { signals, evidence };
  }

  countLinearSegments() {
    if (this.mouseEvents.length < 5) return 0;

    let linearCount = 0;
    for (let i = 2; i < this.mouseEvents.length; i++) {
      const p1 = this.mouseEvents[i - 2];
      const p2 = this.mouseEvents[i - 1];
      const p3 = this.mouseEvents[i];

      // Calculate cross product to detect collinearity
      const crossProduct = Math.abs(
        (p2.x - p1.x) * (p3.y - p1.y) - (p2.y - p1.y) * (p3.x - p1.x)
      );

      if (crossProduct < 50) { // Threshold for "linear"
        linearCount++;
      }
    }

    return linearCount;
  }

  analyzeMovementDirections() {
    if (this.mouseEvents.length < 3) return { directionChanges: 0 };

    let directionChanges = 0;
    let prevAngle = null;

    for (let i = 1; i < this.mouseEvents.length; i++) {
      const curr = this.mouseEvents[i];
      const prev = this.mouseEvents[i - 1];

      const angle = Math.atan2(curr.dy, curr.dx);

      if (prevAngle !== null) {
        const angleDiff = Math.abs(angle - prevAngle);
        if (angleDiff > 0.2) { // Significant direction change
          directionChanges++;
        }
      }

      prevAngle = angle;
    }

    return { directionChanges };
  }

  analyzeClickPatterns() {
    if (this.clickEvents.length === 0) {
      return { signals: [], evidence: { reason: 'no-clicks' } };
    }

    const signals = [];
    const evidence = {
      clickCount: this.clickEvents.length,
      avgClickInterval: 0,
      suspiciousClickIntervals: 0
    };

    // Only analyze if we have substantial click data
    if (this.clickEvents.length < 5) {
      return { signals, evidence };
    }

    // Analyze click intervals
    const intervals = [];
    for (let i = 1; i < this.clickEvents.length; i++) {
      intervals.push(this.clickEvents[i].time - this.clickEvents[i - 1].time);
    }

    if (intervals.length > 0) {
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      evidence.avgClickInterval = Math.round(avgInterval);

      // Bots click at suspiciously regular intervals
      // Require VERY strict timing (std < 10% of mean) with many clicks
      const stdInterval = Math.sqrt(
        intervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length
      );

      if (stdInterval < avgInterval * 0.1 && intervals.length >= 8) {
        signals.push({
          key: 'suspiciousClickCadence',
          label: 'Clicks occur at suspiciously regular intervals',
          value: true,
          confidence: 70,
          weight: 5
        });
        evidence.suspiciousClickIntervals = intervals.filter(
          i => Math.abs(i - avgInterval) < avgInterval * 0.05
        ).length;
      }
    }

    // Check for instant clicks - DISABLED for normal users
    // Normal users may click immediately after page load
    // Only flag if MOST clicks are instant (>70%) after significant interaction
    const instantClicks = this.clickEvents.filter(c =>
      c.elapsed > 0 && c.elapsed < 50
    ).length;

    if (instantClicks > this.clickEvents.length * 0.7 && this.clickEvents.length >= 20) {
      signals.push({
        key: 'instantClicks',
        label: 'Clicks happen too instantly after page load',
        value: true,
        confidence: 65,
        weight: 4
      });
    }

    return { signals, evidence };
  }

  analyzeScrollBehavior() {
    if (this.scrollEvents.length === 0) {
      return { signals: [], evidence: { reason: 'no-scrolling' } };
    }

    const signals = [];
    const evidence = {
      scrollEventCount: this.scrollEvents.length,
      totalScrollDistance: 0,
      avgScrollDistance: 0
    };

    // Analyze scroll distances
    const scrollDistances = [];
    for (let i = 1; i < this.scrollEvents.length; i++) {
      const distance = Math.abs(
        this.scrollEvents[i].scrollY - this.scrollEvents[i - 1].scrollY
      );
      scrollDistances.push(distance);
      evidence.totalScrollDistance += distance;
    }

    if (scrollDistances.length > 0) {
      evidence.avgScrollDistance = Math.round(evidence.totalScrollDistance / scrollDistances.length);

      // Bots scroll in very regular increments
      // Require VERY strict regularity (std < 12% of mean) with many scroll events
      const avgDistance = evidence.avgScrollDistance;
      const stdDistance = Math.sqrt(
        scrollDistances.reduce((sum, d) => sum + Math.pow(d - avgDistance, 2), 0) / scrollDistances.length
      );

      if (stdDistance < avgDistance * 0.12 && scrollDistances.length >= 8) {
        signals.push({
          key: 'suspiciousScrollPattern',
          label: 'Scrolling occurs in suspiciously regular increments',
          value: true,
          confidence: 60,
          weight: 3
        });
      }
    }

    return { signals, evidence };
  }

  analyzeKeyboardBehavior() {
    if (this.keyboardEvents.length === 0) {
      return { signals: [], evidence: { reason: 'no-keyboard-input' } };
    }

    const signals = [];
    const evidence = {
      totalKeystrokes: this.keyboardEvents.length,
      keyDownUpPairs: 0,
      avgKeystrokeInterval: 0
    };

    // Analyze keystroke pairs (down-up)
    let keyDownTimes = {};
    const keystrokeDurations = [];

    this.keyboardEvents.forEach((event) => {
      if (event.type === 'keydown') {
        keyDownTimes[event.key] = event.time;
      } else if (event.type === 'keyup' && keyDownTimes[event.key]) {
        const duration = event.time - keyDownTimes[event.key];
        keystrokeDurations.push(duration);
        evidence.keyDownUpPairs++;
        delete keyDownTimes[event.key];
      }
    });

    // Bots type at perfect speed
    // Require VERY strict timing consistency (std < 5%) with many keystrokes
    if (keystrokeDurations.length >= 10) {
      const avgDuration = keystrokeDurations.reduce((a, b) => a + b, 0) / keystrokeDurations.length;
      const stdDuration = Math.sqrt(
        keystrokeDurations.reduce((sum, d) => sum + Math.pow(d - avgDuration, 2), 0) / keystrokeDurations.length
      );

      evidence.avgKeystrokeInterval = Math.round(avgDuration);

      // Only flag if EXTREMELY consistent
      if (stdDuration < avgDuration * 0.05 && keystrokeDurations.length >= 15) {
        signals.push({
          key: 'suspiciousKeystrokeTiming',
          label: 'Keystroke timing is suspiciously consistent',
          value: true,
          confidence: 65,
          weight: 4
        });
      }
    }

    return { signals, evidence };
  }

  analyzeFormFilling() {
    if (this.formInteractions.length === 0) {
      return { signals: [], evidence: { reason: 'no-form-interaction' } };
    }

    const signals = [];
    const evidence = {
      totalInteractions: this.formInteractions.length,
      avgInputLength: 0,
      suspiciousFillPatterns: 0
    };

    // Only analyze if we have substantial form interaction
    if (this.formInteractions.length < 5) {
      return { signals, evidence };
    }

    // Analyze form filling speed
    const inputEvents = this.formInteractions.filter(f => f.type === 'text');
    if (inputEvents.length >= 8) {
      const inputTimes = [];
      for (let i = 1; i < inputEvents.length; i++) {
        inputTimes.push(inputEvents[i].time - inputEvents[i - 1].time);
      }

      const avgInputTime = inputTimes.reduce((a, b) => a + b, 0) / inputTimes.length;

      // Bots fill forms at inhuman speed
      // Only flag if VERY fast (<20ms per input) with many inputs
      if (avgInputTime < 20 && inputEvents.length >= 15) {
        signals.push({
          key: 'inhumanFormFillingSpeed',
          label: 'Form is being filled at inhuman speed',
          value: true,
          confidence: 75,
          weight: 6
        });
      }

      // Perfect form fill (no corrections/backspace)
      // Only flag with extremely perfect patterns
      const totalChars = this.formInteractions.reduce((sum, f) => sum + f.value, 0);
      if (totalChars > 50 && inputEvents.length === totalChars * 0.98 && inputEvents.length >= 50) {
        // Almost perfect character-to-event ratio suggests no corrections
        signals.push({
          key: 'perfectFormFill',
          label: 'Form filled perfectly without corrections',
          value: true,
          confidence: 70,
          weight: 5
        });
      }
    }

    return { signals, evidence };
  }

  generateSignals() {
    const allSignals = [];

    const mouseSignals = this.analyzeMouseMovement();
    allSignals.push(...mouseSignals.signals);

    const clickSignals = this.analyzeClickPatterns();
    allSignals.push(...clickSignals.signals);

    const scrollSignals = this.analyzeScrollBehavior();
    allSignals.push(...scrollSignals.signals);

    const keyboardSignals = this.analyzeKeyboardBehavior();
    allSignals.push(...keyboardSignals.signals);

    const formSignals = this.analyzeFormFilling();
    allSignals.push(...formSignals.signals);

    // Convert to detector results
    return allSignals.map(signal => {
      const rule = resolveRule(signal.key);
      return createDetectorResult({
        key: signal.key,
        label: signal.label,
        value: signal.value,
        evidence: signal,
        category: 'behavior',
        severity: rule.severity || 'soft',
        weight: signal.weight,
        confidence: signal.confidence,
        state: signal.value ? 'suspicious' : 'ok'
      });
    });
  }

  stop() {
    this.isTracking = false;
  }

  getState() {
    return {
      mouseEvents: this.mouseEvents,
      clickEvents: this.clickEvents,
      scrollEvents: this.scrollEvents,
      keyboardEvents: this.keyboardEvents,
      focusEvents: this.focusEvents,
      formInteractions: this.formInteractions,
      elapsedTime: performance.now() - this.startTime
    };
  }
}

// Create singleton instance
let behaviorTracker = null;

export function initializeAdvancedBehaviorTracking() {
  if (!behaviorTracker) {
    behaviorTracker = new AdvancedBehaviorTracker();
    behaviorTracker.start();
  }
  return behaviorTracker;
}

export function getAdvancedBehaviorTracker() {
  return behaviorTracker || initializeAdvancedBehaviorTracking();
}

export function runAdvancedBehaviorDetection() {
  const tracker = getAdvancedBehaviorTracker();
  const signals = tracker.generateSignals();

  return {
    signals,
    evidence: {
      state: tracker.getState(),
      analysis: {
        mouseMovement: tracker.analyzeMouseMovement(),
        clickPatterns: tracker.analyzeClickPatterns(),
        scrollBehavior: tracker.analyzeScrollBehavior(),
        keyboardBehavior: tracker.analyzeKeyboardBehavior(),
        formFilling: tracker.analyzeFormFilling()
      }
    }
  };
}
