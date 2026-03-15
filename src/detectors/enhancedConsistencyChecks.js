import { createDetectorResult, createWeakCheck, STATES } from '../schema/detectorTypes.js';
import { uaIsChromiumFamily } from './automationArtifacts.js';

/**
 * Enhanced Consistency Checks
 * Stricter validation for consistency between browser claims and actual capabilities
 */

function validatePluginConsistencyStrict(ua) {
  const chromium = uaIsChromiumFamily(ua);
  const issues = [];

  try {
    const plugins = navigator.plugins || { length: 0 };
    const mimeTypes = navigator.mimeTypes || { length: 0 };

    // On Linux Chromium, zero plugins is legitimately possible (Slack, Discord, VSCode)
    // But on Windows/Mac Chromium, it suggests bot activity
    const isLinux = /Linux/i.test(ua);
    const isMacOS = /Mac os x|Macintosh/i.test(ua);
    const isWindows = /Windows/i.test(ua);

    if (chromium && plugins.length === 0 && !isLinux) {
      if (isWindows || isMacOS) {
        issues.push({
          type: 'zero-plugins-on-supported-platform',
          platform: isWindows ? 'windows' : 'macos',
          severity: 'hard',
          confidence: 0.75
        });
      }
    }

    // Check MIME types match plugins
    if (plugins.length > 0 && mimeTypes.length === 0) {
      issues.push({
        type: 'plugins-without-mimetypes',
        severity: 'soft',
        confidence: 0.65
      });
    }

    // Validate individual plugin structures
    for (let i = 0; i < Math.min(plugins.length, 5); i++) {
      const plugin = plugins[i];
      if (!plugin || typeof plugin.name !== 'string' || typeof plugin.version !== 'string') {
        issues.push({
          type: 'malformed-plugin-structure',
          index: i,
          severity: 'soft',
          confidence: 0.60
        });
      }
    }

    // Check for known legitimate plugins across platforms
    if (isWindows || isMacOS) {
      const pluginNames = Array.from(plugins).map(p => (p.name || '').toLowerCase());
      const hasLegitimatePlugins = pluginNames.some(n =>
        /flash|pdf|silver|java|quadlet|adobe|windows media/i.test(n)
      );

      // If Chromium on Windows/Mac with plugins, at least some should be known
      if (chromium && plugins.length > 0 && !hasLegitimatePlugins) {
        issues.push({
          type: 'unknown-plugin-configuration',
          severity: 'soft',
          confidence: 0.62
        });
      }
    }
  } catch (err) {
    // Ignore errors
  }

  return { ok: issues.length === 0, issues };
}

function validateAudioVoicesConsistency(ua) {
  const issues = [];

  try {
    const voices = window.speechSynthesis?.getVoices?.() || [];
    if (voices.length === 0) {
      return { ok: true, count: 0, issues };
    }

    // Different voice sets per platform
    const isWindows = /Windows/i.test(ua);
    const isMacOS = /Mac os x|Macintosh/i.test(ua);
    const isLinux = /Linux/i.test(ua);
    const isAndroid = /Android/i.test(ua);
    const isIOS = /iPhone|iPad|iPod/i.test(ua);

    const voiceLangs = new Set(voices.map(v => v.lang?.split('-')[0]));

    // Windows should have many voices
    if (isWindows && voices.length < 3) {
      issues.push({
        type: 'suspiciously-few-voices-windows',
        count: voices.length,
        confidence: 0.60
      });
    }

    // macOS should have default English voice
    if (isMacOS) {
      const hasEnglish = Array.from(voiceLangs).some(l => /en|EN/.test(l));
      if (!hasEnglish) {
        issues.push({
          type: 'missing-english-voice-macos',
          confidence: 0.62
        });
      }
    }

    // Platform-specific voice names
    const voiceNames = voices.map(v => (v.name || '').toLowerCase());
    if (isWindows && !voiceNames.some(n => /zira|david|hazel/i.test(n)) && voices.length > 0) {
      issues.push({
        type: 'unexpected-voice-set-windows',
        confidence: 0.58
      });
    }

    // Suspicious: identical voice count across samples (cached list)
    return { ok: issues.length === 0, count: voices.length, issues };
  } catch (err) {
    return { ok: true, count: 0, issues };
  }
}

function validateMemoryValuesStrict(ua) {
  const issues = [];

  try {
    const mem = navigator.deviceMemory;
    if (!mem) {
      return { ok: true, issues };
    }

    // Valid values: 0.25, 0.5, 1, 2, 4, 8, 16, 32, 64
    const validValues = [0.25, 0.5, 1, 2, 4, 8, 16, 32, 64];
    if (!validValues.includes(mem)) {
      issues.push({
        type: 'invalid-device-memory-value',
        value: mem,
        severity: 'hard',
        confidence: 0.78
      });
    }

    // Suspicious combinations
    const isLowEndDevice = /Android.*SM-A|iPhone 6|budgetDevice/i.test(ua);
    const isHighEndDevice = /iPhone 14|iPhone 15|Pixel 7|Galaxy S21/i.test(ua);

    // Low-end device claiming 64GB memory
    if (isLowEndDevice && mem >= 32) {
      issues.push({
        type: 'device-memory-mismatch-high',
        deviceClass: 'low-end',
        memory: mem,
        severity: 'hard',
        confidence: 0.75
      });
    }

    // High-end device claiming 0.5GB memory
    if (isHighEndDevice && mem < 2) {
      issues.push({
        type: 'device-memory-mismatch-low',
        deviceClass: 'high-end',
        memory: mem,
        severity: 'hard',
        confidence: 0.75
      });
    }

  } catch (err) {
    // Ignore
  }

  return { ok: issues.length === 0, issues };
}

function validateWebGLVendorPlatformMatch(ua, webglSummary) {
  const issues = [];

  if (!webglSummary || webglSummary.state === 'unavailable') {
    return { ok: true, issues };
  }

  try {
    const renderer = (webglSummary.unmasked_renderer || '').toLowerCase();
    const vendor = (webglSummary.unmasked_vendor || '').toLowerCase();

    const isWindows = /Windows/i.test(ua);
    const isMacOS = /Mac os x|Macintosh/i.test(ua);
    const isLinux = /Linux/i.test(ua);

    // ANGLE only appears on Windows
    if (renderer.includes('angle') && !isWindows) {
      issues.push({
        type: 'angle-no-windows',
        renderer,
        platform: isMacOS ? 'macos' : 'linux',
        confidence: 0.72
      });
    }

    // SwiftShader appears on buggy implementations
    if (renderer.includes('swiftshader')) {
      issues.push({
        type: 'software-rendering-detected',
        renderer,
        confidence: 0.70
      });
    }

    // macOS should have Metal, not ANGLE
    if (isMacOS && renderer.includes('angle')) {
      issues.push({
        type: 'angle-on-macos',
        confidence: 0.75
      });
    }

    // Check vendor platform consistency
    if (vendor.includes('nvidia') && isMacOS && !renderer.includes('eGPU')) {
      issues.push({
        type: 'nvidia-gpu-on-macos',
        confidence: 0.68
      });
    }

  } catch (err) {
    // Ignore
  }

  return { ok: issues.length === 0, issues };
}

function validateTouchCapabilityConsistency(ua) {
  const issues = [];

  try {
    const isMobileUA = /Android|iPhone|iPad|iPod|BlackBerry|Mobile|Tablet/i.test(ua);
    const touchPoints = Number(navigator.maxTouchPoints || 0);
    const hasTouchEvent = ('ontouchstart' in window);
    const pointerTypes = navigator.pointerEnabled === true ? 'pointer-enabled' : 'legacy';

    // Mobile UA should support touch
    if (isMobileUA && touchPoints === 0 && !hasTouchEvent) {
      issues.push({
        type: 'mobile-ua-no-touch-support',
        severity: 'hard',
        confidence: 0.75
      });
    }

    // Desktop UA + huge touch points is suspicious
    if (!isMobileUA && touchPoints > 20) {
      issues.push({
        type: 'desktop-ua-excessive-touchpoints',
        touchPoints,
        confidence: 0.65
      });
    }

    // Desktop UA + single touch point is increasingly suspicious (laptops with touchscreen)
    // But iPad + Magic Keyboard is legitimate, so check for size claims
    const isTouchscreenLaptop = !isMobileUA && touchPoints === 1;
    if (isTouchscreenLaptop) {
      // This is actually legitimate for modern laptops
      // Don't flag as issue
    }

    // Mobile device claiming iPad resolution but no touch
    const hasMultipleScreenResolutions = /iPad.*\(2048;/i.test(ua);
    if (!isMobileUA && hasMultipleScreenResolutions && touchPoints === 0) {
      issues.push({
        type: 'tablet-resolution-no-touch',
        confidence: 0.68
      });
    }

  } catch (err) {
    // Ignore
  }

  return { ok: issues.length === 0, issues };
}

function validateFontLoadingConsistency() {
  const issues = [];

  try {
    // Check which fonts are available
    const testFonts = ('Arial,Courier,Georgia,Helvetica,Impact,Lucida Grande,' +
                      'Tahoma,Times New Roman,Trebuchet MS,Verdana,serif,sans-serif,' +
                      'monospace').split(',');

    const availableFonts = [];
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    if (ctx) {
      const testString = 'Mg';
      const getWidth = (font) => {
        ctx.font = `16px ${font}`;
        const { width } = ctx.measureText(testString);
        return width;
      };

      const baselineWidth = getWidth('Arial');

      testFonts.forEach(font => {
        const width = getWidth(font);
        if (Math.abs(width - baselineWidth) > 0.1) {
          availableFonts.push(font.trim());
        }
      });

      // Suspiciously few unique fonts (cached font list)
      if (availableFonts.length < 5) {
        issues.push({
          type: 'suspiciously-few-unique-fonts',
          count: availableFonts.length,
          confidence: 0.58
        });
      }

      // Check for weird font mixtures
      const hasSerifFonts = availableFonts.some(f => /Serif|Georgia|Times|Garamond/i.test(f));
      const hasSansSerifFonts = availableFonts.some(f => /Arial|Helvetica|Verdana/i.test(f));

      if (!hasSerifFonts || !hasSansSerifFonts) {
        issues.push({
          type: 'unbalanced-font-families',
          hasSerif: hasSerifFonts,
          hasSansSerif: hasSansSerifFonts,
          confidence: 0.55
        });
      }
    }

  } catch (err) {
    // Ignore
  }

  return { ok: issues.length === 0, issues };
}

export function runEnhancedConsistencyChecks(ua, webglSummary) {
  const signals = [];
  const evidence = {};

  // Enhanced plugin validation
  const pluginCheck = validatePluginConsistencyStrict(ua);
  evidence.pluginConsistency = pluginCheck;

  if (pluginCheck.issues.length > 0) {
    pluginCheck.issues.forEach(issue => {
      if (issue.severity === 'hard') {
        signals.push(
          createDetectorResult({
            key: `pluginConsistencyIssue_${issue.type}`,
            label: 'Plugin Consistency Issue (Enhanced)',
            value: true,
            evidence: issue,
            category: 'consistency',
            severity: 'hard',
            weight: 7,
            confidence: Math.round(issue.confidence * 100),
            state: 'suspicious'
          })
        );
      }
    });
  }

  // Enhanced audio voice validation
  const audioVoiceCheck = validateAudioVoicesConsistency(ua);
  evidence.audioVoices = audioVoiceCheck;

  if (audioVoiceCheck.issues.length > 0) {
    audioVoiceCheck.issues.forEach(issue => {
      signals.push(
        createDetectorResult({
          key: `audioVoiceIssue_${issue.type}`,
          label: 'Audio Voice Consistency Issue (Enhanced)',
          value: true,
          evidence: issue,
          category: 'consistency',
          severity: 'soft',
          weight: 4,
          confidence: Math.round(issue.confidence * 100),
          state: 'suspicious'
        })
      );
    });
  }

  // Enhanced memory validation
  const memoryCheck = validateMemoryValuesStrict(ua);
  evidence.memory = memoryCheck;

  if (memoryCheck.issues.length > 0) {
    memoryCheck.issues.forEach(issue => {
      signals.push(
        createDetectorResult({
          key: `memoryIssue_${issue.type}`,
          label: 'Device Memory Consistency Issue (Enhanced)',
          value: true,
          evidence: issue,
          category: issue.severity === 'hard' ? 'environment' : 'consistency',
          severity: issue.severity || 'soft',
          weight: issue.severity === 'hard' ? 6 : 4,
          confidence: Math.round(issue.confidence * 100),
          state: 'suspicious'
        })
      );
    });
  }

  // Enhanced WebGL platform matching
  const webglCheck = validateWebGLVendorPlatformMatch(ua, webglSummary);
  evidence.webglConsistency = webglCheck;

  if (webglCheck.issues.length > 0) {
    webglCheck.issues.forEach(issue => {
      signals.push(
        createDetectorResult({
          key: `webglIssue_${issue.type}`,
          label: 'WebGL Platform Consistency Issue (Enhanced)',
          value: true,
          evidence: issue,
          category: 'consistency',
          severity: 'soft',
          weight: 5,
          confidence: Math.round(issue.confidence * 100),
          state: 'suspicious'
        })
      );
    });
  }

  // Enhanced touch capability validation
  const touchCheck = validateTouchCapabilityConsistency(ua);
  evidence.touchCapability = touchCheck;

  if (touchCheck.issues.length > 0) {
    touchCheck.issues.forEach(issue => {
      signals.push(
        createDetectorResult({
          key: `touchIssue_${issue.type}`,
          label: 'Touch Capability Consistency Issue (Enhanced)',
          value: true,
          evidence: issue,
          category: 'consistency',
          severity: issue.severity || 'soft',
          weight: issue.severity === 'hard' ? 6 : 4,
          confidence: Math.round(issue.confidence * 100),
          state: 'suspicious'
        })
      );
    });
  }

  // Font loading consistency
  const fontCheck = validateFontLoadingConsistency();
  evidence.fontConsistency = fontCheck;

  if (fontCheck.issues.length > 0) {
    fontCheck.issues.forEach(issue => {
      signals.push(
        createDetectorResult({
          key: `fontIssue_${issue.type}`,
          label: 'Font Loading Consistency Issue (Enhanced)',
          value: true,
          evidence: issue,
          category: 'fingerprint',
          severity: 'soft',
          weight: 3,
          confidence: Math.round(issue.confidence * 100),
          state: 'suspicious'
        })
      );
    });
  }

  return { signals, evidence };
}
