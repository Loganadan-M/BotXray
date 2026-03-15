import { createDetectorResult, STATES } from '../schema/detectorTypes.js';
import { round } from '../utils/common.js';

/**
 * Advanced GPU and Rendering Fingerprinting
 * Detects: software rendering, emulation, GPU timing anomalies
 */

function detectWebAssemblyTiming() {
  const results = {
    supported: typeof WebAssembly !== 'undefined',
    performanceIndicators: []
  };

  if (!results.supported) {
    return results;
  }

  try {
    // Create a simple WASM module for timing tests
    const wasmCode = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
      0x03, 0x02, 0x01, 0x00,
      0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
    ]);

    const wasmModule = new WebAssembly.Module(wasmCode);
    const wasmInstance = new WebAssembly.Instance(wasmModule);

    // Time WASM function execution (simple addition)
    const samples = [];
    for (let i = 0; i < 100; i++) {
      const start = performance.now();
      for (let j = 0; j < 1000; j++) {
        wasmInstance.exports[0](i, j); // Add operation
      }
      samples.push(performance.now() - start);
    }

    const avgTime = samples.reduce((a, b) => a + b, 0) / samples.length;
    const minTime = Math.min(...samples);

    results.performanceIndicators = {
      avgExecutionTime: round(avgTime, 3),
      minExecutionTime: round(minTime, 3)
    };

    // Suspicion: overly fast execution (emulation with JIT)
    if (minTime < 0.1) {
      results.performanceIndicators.suspicion = 'suspiciously-fast-wasm-execution';
      results.performanceIndicators.suspicionConfidence = 0.58;
    }

    // Suspicion: overly slow execution (software emulation)
    if (avgTime > 10) {
      results.performanceIndicators.suspicion = 'suspiciously-slow-wasm-execution';
      results.performanceIndicators.suspicionConfidence = 0.55;
    }
  } catch (err) {
    results.error = String(err);
  }

  return results;
}

function detectShaderCompilationTiming() {
  const results = {
    supported: !!document.createElement('canvas').getContext('webgl'),
    shaderTimings: []
  };

  if (!results.supported) {
    return results;
  }

  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl');

    if (!gl) {
      results.error = 'WebGL context unavailable';
      return results;
    }

    // Simple vertex shader
    const vertexShaderCode = `
      attribute vec4 position;
      void main() {
        gl_Position = position;
      }
    `;

    // Simple fragment shader
    const fragmentShaderCode = `
      precision mediump float;
      void main() {
        gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0);
      }
    `;

    const shaders = [];
    shaders.push({ type: gl.VERTEX_SHADER, code: vertexShaderCode });
    shaders.push({ type: gl.FRAGMENT_SHADER, code: fragmentShaderCode });

    const timings = [];
    shaders.forEach(({ type, code }) => {
      const shader = gl.createShader(type);
      gl.shaderSource(shader, code);

      const start = performance.now();
      gl.compileShader(shader);
      const compilationTime = performance.now() - start;

      timings.push({
        type: type === gl.VERTEX_SHADER ? 'vertex' : 'fragment',
        compilationTime: round(compilationTime, 3)
      });

      gl.deleteShader(shader);
    });

    results.shaderTimings = timings;

    // Suspicion: extremely fast shader compilation (hardware GPU)
    const avgTime = timings.reduce((a, b) => a + b.compilationTime, 0) / timings.length;
    if (avgTime < 0.5) {
      results.suspicion = 'suspicious-fast-shader-compilation';
      results.suspicionConfidence = 0.60;
    }

    // Suspicion: very slow shader compilation (software rendering)
    if (avgTime > 50) {
      results.suspicion = 'suspicious-slow-shader-compilation';
      results.suspicionConfidence = 0.62;
    }

    gl.getExtension('WEBGL_lose_context').loseContext();
  } catch (err) {
    results.error = String(err);
  }

  return results;
}

function detectTextureRenderingBandwidth() {
  const results = {
    supported: false,
    textureOperations: []
  };

  try {
    const canvas = document.createElement('canvas');
    canvas.width = 512;
    canvas.height = 512;
    const gl = canvas.getContext('webgl');

    if (!gl) {
      return results;
    }

    results.supported = true;

    // Create test texture
    const texture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);

    // Upload texture data multiple times and measure
    const textureData = new Uint8Array(512 * 512 * 4);
    const timings = [];

    for (let i = 0; i < 5; i++) {
      const start = performance.now();
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 512, 512, 0, gl.RGBA, gl.UNSIGNED_BYTE, textureData);
      gl.readPixels(0, 0, 512, 512, gl.RGBA, gl.UNSIGNED_BYTE, new Uint8Array(512 * 512 * 4));
      timings.push(performance.now() - start);
    }

    const avgTime = timings.reduce((a, b) => a + b, 0) / timings.length;
    results.textureOperations = {
      operations: 5,
      avgTimeMs: round(avgTime, 3),
      totalTimeMs: round(timings.reduce((a, b) => a + b), 2)
    };

    // Memory bandwidth estimation
    const dataSizeBytes = 512 * 512 * 4 * 5;
    const bandwidthMBps = (dataSizeBytes / (1024 * 1024)) / (avgTime / 1000);
    results.textureOperations.estimatedBandwidthMBps = round(bandwidthMBps, 2);

    // Suspicion: extremely low bandwidth (CPU-based)
    if (bandwidthMBps < 100) {
      results.suspicion = 'low-gpu-bandwidth';
      results.suspicionConfidence = 0.58;
    }

    gl.getExtension('WEBGL_lose_context').loseContext();
  } catch (err) {
    results.error = String(err);
  }

  return results;
}

function detectGradientPrecision() {
  const results = {
    canvas: null,
    colorValues: [],
    precision: 'unknown'
  };

  try {
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 256;
    const ctx = canvas.getContext('2d');

    if (!ctx) return results;

    results.canvas = canvas;

    // Create linear gradient
    const gradient = ctx.createLinearGradient(0, 0, 256, 0);
    gradient.addColorStop(0, 'rgb(0, 0, 0)');
    gradient.addColorStop(1, 'rgb(255, 255, 255)');

    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 256, 256);

    // Sample pixel values at key positions
    const imageData = ctx.getImageData(0, 0, 256, 256);
    const data = imageData.data;

    const samples = [0, 64, 128, 192, 255];
    const colorValues = [];

    samples.forEach(pos => {
      const pixelIndex = pos * 4;
      colorValues.push({
        position: pos,
        r: data[pixelIndex],
        g: data[pixelIndex + 1],
        b: data[pixelIndex + 2]
      });
    });

    results.colorValues = colorValues;

    // Check for suspicious precision patterns
    const redValues = colorValues.map(v => v.r);
    const uniqueValues = new Set(redValues);

    if (uniqueValues.size === 1) {
      results.precision = 'suspiciously-uniform';
      results.suspicion = 'gradient-precision-anomaly';
      results.suspicionConfidence = 0.62;
    } else if (uniqueValues.size > redValues.length * 0.8) {
      results.precision = 'normal-gradient-precision';
    }
  } catch (err) {
    results.error = String(err);
  }

  return results;
}

function detectWebGPUSupport() {
  const results = {
    supported: !!navigator.gpu,
    adapter: null,
    limitations: []
  };

  if (!results.supported) {
    return results;
  }

  try {
    navigator.gpu.requestAdapter().then(adapter => {
      if (!adapter) {
        results.limitations.push('no-adapter-available');
        return;
      }

      results.adapter = {
        name: adapter.name || 'unknown',
        features: Array.from(adapter.features || []).slice(0, 5)
      };

      // Check for limitations (indicates software rendering)
      adapter.limits = adapter.limits || {};
      if (adapter.limits.maxBufferSize && adapter.limits.maxBufferSize < 1024 * 1024 * 100) {
        results.limitations.push('small-max-buffer-size');
      }
    });
  } catch (err) {
    results.error = String(err);
  }

  return results;
}

export function runGPURenderingEnhancements() {
  const signals = [];
  const evidence = {};

  // WASM timing analysis
  const wasmTiming = detectWebAssemblyTiming();
  evidence.wasmTiming = wasmTiming;

  if (wasmTiming.performanceIndicators.suspicion) {
    signals.push(
      createDetectorResult({
        key: 'wasmTimingAnomaly',
        label: 'WebAssembly Timing Anomaly',
        value: true,
        evidence: wasmTiming.performanceIndicators,
        category: 'environment',
        severity: 'soft',
        weight: 4,
        confidence: Math.round(wasmTiming.performanceIndicators.suspicionConfidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Shader compilation timing
  const shaderTiming = detectShaderCompilationTiming();
  evidence.shaderCompilation = shaderTiming;

  if (shaderTiming.suspicion) {
    signals.push(
      createDetectorResult({
        key: 'shaderCompilationAnomaly',
        label: 'WebGL Shader Compilation Anomaly',
        value: true,
        evidence: shaderTiming.shaderTimings,
        category: 'environment',
        severity: 'soft',
        weight: 4,
        confidence: Math.round(shaderTiming.suspicionConfidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Texture rendering bandwidth
  const textureBandwidth = detectTextureRenderingBandwidth();
  evidence.textureRendering = textureBandwidth;

  if (textureBandwidth.suspicion) {
    signals.push(
      createDetectorResult({
        key: 'textureRenderingBandwidthAnomaly',
        label: 'GPU Texture Rendering Anomaly',
        value: true,
        evidence: textureBandwidth.textureOperations,
        category: 'environment',
        severity: 'soft',
        weight: 4,
        confidence: Math.round(textureBandwidth.suspicionConfidence * 100),
        state: 'suspicious'
      })
    );
  }

  // Gradient precision
  const gradientPrecision = detectGradientPrecision();
  evidence.gradientPrecision = gradientPrecision;

  if (gradientPrecision.suspicion) {
    signals.push(
      createDetectorResult({
        key: 'canvasGradientPrecision',
        label: 'Canvas Gradient Rendering Precision Anomaly',
        value: true,
        evidence: gradientPrecision.colorValues,
        category: 'fingerprint',
        severity: 'soft',
        weight: 3,
        confidence: Math.round(gradientPrecision.suspicionConfidence * 100),
        state: 'suspicious'
      })
    );
  }

  // WebGPU support
  const webgpu = detectWebGPUSupport();
  evidence.webgpu = webgpu;

  if (webgpu.limitations.length > 0) {
    signals.push(
      createDetectorResult({
        key: 'webgpuLimitations',
        label: 'WebGPU Capability Limitations',
        value: true,
        evidence: webgpu.limitations,
        category: 'environment',
        severity: 'soft',
        weight: 2,
        confidence: 50,
        state: 'suspicious'
      })
    );
  }

  return { signals, evidence };
}
