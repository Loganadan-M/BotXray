/**
 * Comprehensive Bot Detection Testing Suite
 * Tests v4.0 system against various bot types
 */

// ============================================================================
// TEST SCENARIO FRAMEWORK
// ============================================================================

class BotSimulator {
  constructor(name, type) {
    this.name = name;
    this.type = type;
    this.setup = () => {};
    this.teardown = () => {};
  }

  async run(detectionFunction) {
    console.log(`\n${'='.repeat(80)}`);
    console.log(`🤖 Testing: ${this.name} (${this.type})`);
    console.log(`${'='.repeat(80)}`);

    try {
      this.setup();
      const startTime = performance.now();
      const result = await detectionFunction();
      const elapsedMs = performance.now() - startTime;

      return {
        name: this.name,
        type: this.type,
        score100: result.score100,
        botScore: result.botScore,
        riskLabel: result.riskLabel,
        action: result.action,
        signalCount: result.signals?.length || 0,
        criticalHits: result.categoryBreakdown?.automation || 0,
        elapsedMs,
        signals: result.signals?.map(s => ({ key: s.key, label: s.label, confidence: s.confidence })),
        passed: this.evaluate(result)
      };
    } catch (error) {
      console.error(`❌ Test failed: ${error.message}`);
      return {
        name: this.name,
        type: this.type,
        error: error.message,
        passed: false
      };
    } finally {
      this.teardown();
    }
  }

  evaluate(result) {
    // Override in subclass
    return true;
  }
}

// ============================================================================
// BOT SCENARIO 1: Naive Selenium (Basic)
// ============================================================================

class NaiveSeleniumBot extends BotSimulator {
  constructor() {
    super('Naive Selenium Bot', 'Basic WebDriver');
  }

  setup() {
    // Simulate Selenium artifacts
    window.cdc_adoQpoasnfa76pfcZLmcfl = true;
    window.__selenium_unwrapped = true;

    // Simulate no user interaction
    this.originalChrome = window.chrome;
    if (!window.chrome) {
      window.chrome = { runtime: {} };
    }
  }

  teardown() {
    delete window.cdc_adoQpoasnfa76pfcZLmcfl;
    delete window.__selenium_unwrapped;
    if (!this.originalChrome) {
      delete window.chrome;
    }
  }

  evaluate(result) {
    // Should detect Selenium artifacts
    const hasSeleniumSignals = result.signals?.some(s =>
      s.key.includes('selenium') || s.key.includes('webdriver')
    );

    const score = result.score100;
    const expected = score >= 60; // Should be HIGH risk

    console.log(`Expected: Score ≥ 60 (HIGH) | Actual: ${score} (${result.riskLabel})`);
    console.log(`Selenium detection: ${hasSeleniumSignals ? '✅ DETECTED' : '❌ MISSED'}`);

    return expected && hasSeleniumSignals;
  }
}

// ============================================================================
// BOT SCENARIO 2: Puppeteer with Headless Chrome
// ============================================================================

class PuppeteerBot extends BotSimulator {
  constructor() {
    super('Puppeteer Headless Chrome', 'Framework');
  }

  setup() {
    // Simulate headless indicators
    Object.defineProperty(navigator, 'userAgent', {
      get: () => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0'
    });

    // No webdriver property (modern Puppeteer hides it)
    Object.defineProperty(navigator, 'webdriver', {
      value: undefined
    });

    // Simulate Chrome object
    window.chrome = { runtime: {} };

    // Mock performance.now() with suspicious timing
    const originalPerformance = performance.now;
    performance.now = (() => {
      let counter = 0;
      return () => counter += 0.5; // Perfect 0.5ms increments
    })();
  }

  teardown() {
    // Restore
    delete Object.getOwnPropertyDescriptor(navigator, 'userAgent');
  }

  evaluate(result) {
    const hasHeadlessSignals = result.signals?.some(s =>
      s.key.includes('headless') || s.key.includes('performance')
    );

    const score = result.score100;
    const expected = score >= 50; // Should be MEDIUM-HIGH risk

    console.log(`Expected: Score ≥ 50 (MEDIUM-HIGH) | Actual: ${score} (${result.riskLabel})`);
    console.log(`Headless detection: ${hasHeadlessSignals ? '✅ DETECTED' : '⚠️ PARTIAL'}`);

    return expected && hasHeadlessSignals;
  }
}

// ============================================================================
// BOT SCENARIO 3: Playwright with Stealth Plugin
// ============================================================================

class PlaywrightStealthBot extends BotSimulator {
  constructor() {
    super('Playwright with Stealth Plugin', 'Advanced Framework');
  }

  setup() {
    // Simulate Playwright artifacts
    window.__playwright__ = { version: '1.40.0' };
    window.__pwInitScripts = [];

    // Stealth plugin hides webdriver
    Object.defineProperty(navigator, 'webdriver', {
      value: false,
      configurable: false
    });

    // Patch properties with getters
    const handler = {
      get: (target, prop) => {
        if (prop === 'platform') return 'Linux';
        if (prop === 'hardwareConcurrency') return 8;
        return Reflect.get(target, prop);
      }
    };

    // Simulate proxy wrapping
    this.originalNavigator = window.navigator;
    window.navigator = new Proxy(navigator, handler);
  }

  teardown() {
    // Restore
    delete window.__playwright__;
    delete window.__pwInitScripts;
  }

  evaluate(result) {
    const hasPlaywrightSignals = result.signals?.some(s =>
      s.key.includes('playwright') || s.key.includes('proxy')
    );

    const score = result.score100;
    const expected = score >= 65; // Should be HIGH-CRITICAL risk

    console.log(`Expected: Score ≥ 65 (HIGH) | Actual: ${score} (${result.riskLabel})`);
    console.log(`Playwright detection: ${hasPlaywrightSignals ? '✅ DETECTED' : '⚠️ PARTIAL'}`);
    console.log(`Proxy patching detection: ${result.signals?.some(s => s.key.includes('Proxy')) ? '✅ DETECTED' : '❌ MISSED'}`);

    return expected && hasPlaywrightSignals;
  }
}

// ============================================================================
// BOT SCENARIO 4: Undetected-Chromedriver (Advanced)
// ============================================================================

class UndetectedChromeBot extends BotSimulator {
  constructor() {
    super('Undetected-Chromedriver', 'Advanced Evasion');
  }

  setup() {
    // Modern undetected-chromedriver removes standard markers
    Object.defineProperty(navigator, 'webdriver', {
      value: undefined,
      configurable: true
    });

    // Hide Selenium artifacts
    const keys = Object.getOwnPropertyNames(window);
    keys.forEach(key => {
      if (key.startsWith('cdc_') || key.startsWith('$cdc_')) {
        delete window[key];
      }
    });

    // Patch Function.toString
    const originalToString = Function.prototype.toString;
    Function.prototype.toString = function() {
      if (this === Function.prototype.toString) {
        return 'function toString() { [native code] }';
      }
      return originalToString.call(this);
    };

    // Patch Object.getOwnPropertyDescriptor
    const originalGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    Object.getOwnPropertyDescriptor = function(obj, prop) {
      return originalGetOwnPropertyDescriptor.call(this, obj, prop);
    };

    // Simulate perfect behavior (form filling, mouse movement)
    this.simulatePerfectBehavior();
  }

  simulatePerfectBehavior() {
    // Perfect consistent mouse movement
    this.mouseX = 0;
    this.mouseY = 0;
    this.lastMouseTime = performance.now();

    // Monitor for mouse tracking
    document.addEventListener('mousemove', (e) => {
      this.mouseX = e.clientX;
      this.mouseY = e.clientY;
      this.lastMouseTime = performance.now();
    });
  }

  teardown() {
    // Cannot easily undo all patches in real scenario
    console.log('Note: Undetected-chromedriver patches may persist');
  }

  evaluate(result) {
    const hasAdvancedEvasionSignals = result.signals?.some(s =>
      s.key.includes('undetectable') || s.key.includes('Advanced') ||
      s.key.includes('performanceNow') || s.key.includes('proxyPatching')
    );

    const score = result.score100;
    const expected = score >= 70; // Should be HIGH-CRITICAL risk

    console.log(`Expected: Score ≥ 70 (HIGH-CRITICAL) | Actual: ${score} (${result.riskLabel})`);
    console.log(`Advanced evasion detection: ${hasAdvancedEvasionSignals ? '✅ DETECTED' : '⚠️ NEEDS WORK'}`);
    console.log(`Signal count: ${result.signals?.length || 0} (expect 8+ from new detectors)`);

    return expected && hasAdvancedEvasionSignals;
  }
}

// ============================================================================
// BOT SCENARIO 5: VPS Bot with Datacenter Characteristics
// ============================================================================

class VPSBot extends BotSimulator {
  constructor() {
    super('VPS/Datacenter Bot', 'Infrastructure-Based');
  }

  setup() {
    // Simulate datacenter characteristics
    Object.defineProperty(navigator, 'deviceMemory', {
      value: 16,
      configurable: true
    });

    Object.defineProperty(navigator, 'hardwareConcurrency', {
      value: 32,
      configurable: true
    });

    // Simulate zero plugins (datacenter)
    Object.defineProperty(navigator, 'plugins', {
      value: { length: 0 },
      configurable: true
    });

    // Mock network connection with datacenter characteristics
    if (navigator.connection) {
      Object.defineProperty(navigator.connection, 'rtt', {
        value: 0.5, // Suspiciously low
        configurable: true
      });

      Object.defineProperty(navigator.connection, 'downlink', {
        value: 1000, // Suspiciously high
        configurable: true
      });
    }

    // Simulate WebGL SwiftShader (software rendering)
    this.mockWebGL();
  }

  mockWebGL() {
    const originalGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function(type) {
      if (type === 'webgl' || type === 'webgl2') {
        const ctx = originalGetContext.call(this, type);
        // Mock SwiftShader renderer
        if (ctx && ctx.getParameter) {
          const origGetParameter = ctx.getParameter;
          ctx.getParameter = function(param) {
            if (param === 37445) { // UNMASKED_RENDERER_WEBGL
              return 'Google SwiftShader';
            }
            return origGetParameter.call(this, param);
          };
        }
        return ctx;
      }
      return originalGetContext.call(this, type);
    };
  }

  teardown() {
    // Restore
    delete Object.getOwnPropertyDescriptor(navigator, 'deviceMemory');
  }

  evaluate(result) {
    const hasDatacenterSignals = result.signals?.some(s =>
      s.key.includes('datacenter') || s.key.includes('WebGL') ||
      s.key.includes('memory') || s.key.includes('plugin')
    );

    const score = result.score100;
    const expected = score >= 50; // Should be MEDIUM-HIGH risk

    console.log(`Expected: Score ≥ 50 (MEDIUM-HIGH) | Actual: ${score} (${result.riskLabel})`);
    console.log(`Datacenter detection: ${hasDatacenterSignals ? '✅ DETECTED' : '⚠️ PARTIAL'}`);

    return expected;
  }
}

// ============================================================================
// BOT SCENARIO 6: Behavioral Bot (Well-Crafted)
// ============================================================================

class BehavioralBot extends BotSimulator {
  constructor() {
    super('Behavioral Bot (Well-Crafted)', 'ML/Trained');
  }

  setup() {
    // Perfect form filling with consistent timing
    this.setupFormFillingPattern();

    // Perfect scroll behavior
    this.setupScrollPattern();

    // Perfectly linear mouse movements
    this.setupMousePattern();
  }

  setupFormFillingPattern() {
    // Simulate form interactions with perfect ~100ms delays
    document.addEventListener('focus', (e) => {
      if (e.target?.tagName === 'INPUT') {
        setTimeout(() => {
          e.target.value = 'test@example.com';
          e.target.dispatchEvent(new Event('input', { bubbles: true }));
        }, 100); // Perfect consistency
      }
    });
  }

  setupScrollPattern() {
    // Simulate scroll events with mechanical timing
    this.scrollInterval = setInterval(() => {
      window.scrollBy(0, 50);
    }, 200); // Perfect 200ms intervals
  }

  setupMousePattern() {
    // Simulate perfectly linear mouse movement
    let progress = 0;
    this.mouseInterval = setInterval(() => {
      progress += 0.01;
      if (progress <= 1) {
        const x = 100 + (progress * 200); // Perfectly linear
        const y = 100 + (progress * 150);
        const event = new MouseEvent('mousemove', { clientX: x, clientY: y });
        document.dispatchEvent(event);
      }
    }, 16); // Consistent 60fps
  }

  teardown() {
    clearInterval(this.scrollInterval);
    clearInterval(this.mouseInterval);
  }

  evaluate(result) {
    const hasBehanioralSignals = result.signals?.some(s =>
      s.key.includes('Cadence') || s.key.includes('Scroll') ||
      s.key.includes('Mouse') || s.key.includes('Acceleration')
    );

    const score = result.score100;
    const expected = score >= 40; // Should be MEDIUM risk minimum

    console.log(`Expected: Score ≥ 40 (MEDIUM) | Actual: ${score} (${result.riskLabel})`);
    console.log(`Behavioral detection: ${hasBehanioralSignals ? '✅ DETECTED' : '⚠️ MISSED'}`);

    return expected && hasBehanioralSignals;
  }
}

// ============================================================================
// LEGITIMATE SCENARIO 1: Real Human (Fast Navigator)
// ============================================================================

class RealHumanFast extends BotSimulator {
  constructor() {
    super('Real Human (Fast Navigator)', 'Legitimate User');
  }

  setup() {
    // Fresh browser state - no modifications
    console.log('✅ No modifications - fresh legitimate instance');
  }

  teardown() {
    // Nothing to clean
  }

  evaluate(result) {
    const score = result.score100;
    const expected = score < 25; // Should be LOW risk

    console.log(`Expected: Score < 25 (LOW) | Actual: ${score} (${result.riskLabel})`);
    console.log(`FALSE POSITIVE CHECK: ${expected ? '✅ PASS - Not flagged as bot' : '❌ FAIL - Incorrectly flagged'}`);

    return expected;
  }
}

// ============================================================================
// LEGITIMATE SCENARIO 2: VPN User
// ============================================================================

class VPNUser extends BotSimulator {
  constructor() {
    super('Legitimate VPN User', 'Legitimate User');
  }

  setup() {
    // Simulate VPN characteristics but legitimate behavior
    Object.defineProperty(navigator, 'language', {
      value: 'en-US',
      configurable: true
    });

    // Normal plugin configuration
    Object.defineProperty(navigator, 'plugins', {
      value: { length: 3 }, // Has some plugins
      configurable: true
    });

    // Simulate natural variance in mouse movement
    document.addEventListener('mousemove', (e) => {
      // Natural but slightly jittered movement
      const jitter = Math.random() * 2 - 1;
      console.log(`Mouse: ${e.clientX + jitter}, ${e.clientY + jitter}`);
    });
  }

  teardown() {
    // Cleanup
  }

  evaluate(result) {
    const score = result.score100;
    const expected = score < 35; // Should be LOW-MEDIUM risk (accounting for VPN)

    console.log(`Expected: Score < 35 (LOW-MEDIUM, accounting for VPN) | Actual: ${score} (${result.riskLabel})`);
    console.log(`FALSE POSITIVE CHECK: ${expected ? '✅ PASS - Not overly penalized' : '⚠️ VPN may trigger some signals'}`);

    return expected;
  }
}

// ============================================================================
// LEGITIMATE SCENARIO 3: Developer on VM
// ============================================================================

class DeveloperVM extends BotSimulator {
  constructor() {
    super('Developer on Virtual Machine', 'Legitimate User (Unusual Config)');
  }

  setup() {
    // VM characteristics but legitimate
    Object.defineProperty(navigator, 'deviceMemory', {
      value: 8, // Reasonable VM allocation
      configurable: true
    });

    Object.defineProperty(navigator, 'hardwareConcurrency', {
      value: 4, // VM cores
      configurable: true
    });

    // Legitimate WebGL (could be software)
    console.log('VM running with standard browser extensions');
  }

  teardown() {
    // Cleanup
  }

  evaluate(result) {
    const score = result.score100;
    const expected = score < 30; // Should be LOW risk (maybe MEDIUM at worst)

    console.log(`Expected: Score < 30 (LOW) | Actual: ${score} (${result.riskLabel})`);
    console.log(`FALSE POSITIVE CHECK: ${expected ? '✅ PASS - VM config acceptable' : '⚠️ May flag some VM aspects'}`);

    return expected;
  }
}

// ============================================================================
// TEST RUNNER
// ============================================================================

export async function runBotDetectionTests(runDetection) {
  const scenarios = [
    // Low-difficulty bots
    new NaiveSeleniumBot(),
    new PuppeteerBot(),

    // Medium-difficulty bots
    new PlaywrightStealthBot(),
    new VPSBot(),

    // High-difficulty bots
    new UndetectedChromeBot(),
    new BehavioralBot(),

    // Legitimate users (false positive prevention)
    new RealHumanFast(),
    new VPNUser(),
    new DeveloperVM()
  ];

  const results = [];
  let passed = 0;
  let failed = 0;

  console.log('\n' + '='.repeat(80));
  console.log('🛡️  ADVANCED BOT DETECTION SYSTEM v4.0 - COMPREHENSIVE TEST SUITE');
  console.log('='.repeat(80));
  console.log(`Testing against ${scenarios.length} bot/user scenarios\n`);

  for (const scenario of scenarios) {
    const result = await scenario.run(runDetection);
    results.push(result);

    if (result.passed) {
      passed++;
      console.log('✅ TEST PASSED');
    } else if (result.error) {
      failed++;
      console.log('❌ TEST ERROR');
    } else {
      failed++;
      console.log('❌ TEST FAILED');
    }
  }

  // Summary Report
  console.log('\n' + '='.repeat(80));
  console.log('📊 TEST SUMMARY REPORT');
  console.log('='.repeat(80));

  const table = results.map(r => ({
    Name: r.name,
    Type: r.type,
    Score: r.score100 !== undefined ? `${r.score100.toFixed(1)}/100` : 'ERROR',
    BotScore: r.botScore !== undefined ? `${r.botScore.toFixed(1)}/25` : '-',
    Risk: r.riskLabel || 'ERROR',
    Signals: r.signalCount || 0,
    Time: r.elapsedMs ? `${r.elapsedMs.toFixed(0)}ms` : '-',
    Result: r.passed ? '✅ PASS' : (r.error ? '❌ ERROR' : '❌ FAIL')
  }));

  console.table(table);

  // Detailed Results
  console.log('\n' + '='.repeat(80));
  console.log('📈 DETAILED RESULTS');
  console.log('='.repeat(80));

  results.forEach((r, idx) => {
    console.log(`\n${idx + 1}. ${r.name}`);
    console.log(`   Type: ${r.type}`);
    console.log(`   Score: ${r.score100 !== undefined ? r.score100.toFixed(1) : 'ERROR'}/100`);
    console.log(`   Bot Score: ${r.botScore !== undefined ? r.botScore.toFixed(1) : 'N/A'}/25`);
    console.log(`   Risk Level: ${r.riskLabel || 'ERROR'}`);
    console.log(`   Action: ${r.action || 'N/A'}`);
    console.log(`   Signals Detected: ${r.signalCount || 0}`);
    console.log(`   Execution Time: ${r.elapsedMs !== undefined ? r.elapsedMs.toFixed(0) : 'N/A'}ms`);
    console.log(`   Result: ${r.passed ? '✅ PASSED' : '❌ FAILED'}`);

    if (r.signals && r.signals.length > 0) {
      console.log(`   Top Signals:`);
      r.signals.slice(0, 5).forEach(s => {
        console.log(`     • ${s.label} (${s.confidence}% confidence)`);
      });
    }
  });

  // Score Analysis
  console.log('\n' + '='.repeat(80));
  console.log('🎯 SCORE ANALYSIS');
  console.log('='.repeat(80));

  const botResults = results.slice(0, 6);
  const humanResults = results.slice(6);

  const botScores = botResults.map(r => r.score100).filter(s => s !== undefined);
  const humanScores = humanResults.map(r => r.score100).filter(s => s !== undefined);

  console.log('\n🤖 BOT DETECTION SCORES:');
  console.log(`  Average: ${(botScores.reduce((a,b) => a+b, 0) / botScores.length).toFixed(1)}/100`);
  console.log(`  Min: ${Math.min(...botScores).toFixed(1)}/100`);
  console.log(`  Max: ${Math.max(...botScores).toFixed(1)}/100`);
  console.log(`  All ≥ 40: ${botScores.every(s => s >= 40) ? '✅ YES' : '❌ NO'}`);

  console.log('\n👤 HUMAN DETECTION SCORES:');
  console.log(`  Average: ${(humanScores.reduce((a,b) => a+b, 0) / humanScores.length).toFixed(1)}/100`);
  console.log(`  Min: ${Math.min(...humanScores).toFixed(1)}/100`);
  console.log(`  Max: ${Math.max(...humanScores).toFixed(1)}/100`);
  console.log(`  All ≤ 35: ${humanScores.every(s => s < 35) ? '✅ YES (Good!)' : '⚠️ Some higher than expected'}`);

  // Distribution
  console.log('\n📊 SCORE DISTRIBUTION:');
  console.log('  Critical (80-100): ' + botResults.filter(r => r.score100 >= 80).length);
  console.log('  High (60-80):      ' + botResults.filter(r => r.score100 >= 60 && r.score100 < 80).length);
  console.log('  Medium (30-60):    ' + botResults.filter(r => r.score100 >= 30 && r.score100 < 60).length);
  console.log('  Low (0-30):        ' + botResults.filter(r => r.score100 < 30).length);

  // Overall Summary
  console.log('\n' + '='.repeat(80));
  console.log('🏆 OVERALL RESULTS');
  console.log('='.repeat(80));
  console.log(`Total Tests: ${results.length}`);
  console.log(`Passed: ✅ ${passed}/${results.length}`);
  console.log(`Failed: ❌ ${failed}/${results.length}`);
  console.log(`Success Rate: ${((passed / results.length) * 100).toFixed(1)}%`);
  console.log('');
  console.log(`Bot Detection: ${botResults.filter(r => r.passed).length}/${botResults.length} passed`);
  console.log(`False Positive Prevention: ${humanResults.filter(r => r.passed).length}/${humanResults.length} passed`);

  if (passed === results.length) {
    console.log('\n🎉 ALL TESTS PASSED! System is working as expected.');
  } else if (passed >= results.length * 0.8) {
    console.log('\n✅ MOSTLY WORKING - Minor issues detected.');
  } else {
    console.log('\n⚠️  NEEDS REVIEW - Multiple issues found.');
  }

  console.log('\n' + '='.repeat(80));

  return {
    totalTests: results.length,
    passed,
    failed,
    successRate: (passed / results.length) * 100,
    results,
    summary: {
      botDetection: {
        count: botResults.length,
        passed: botResults.filter(r => r.passed).length,
        avgScore: botScores.reduce((a,b) => a+b, 0) / botScores.length
      },
      falsePositivePrevention: {
        count: humanResults.length,
        passed: humanResults.filter(r => r.passed).length,
        avgScore: humanScores.reduce((a,b) => a+b, 0) / humanScores.length
      }
    }
  };
}

export {
  NaiveSeleniumBot,
  PuppeteerBot,
  PlaywrightStealthBot,
  UndetectedChromeBot,
  VPSBot,
  BehavioralBot,
  RealHumanFast,
  VPNUser,
  DeveloperVM
};
