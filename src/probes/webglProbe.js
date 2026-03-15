function getContext(type) {
  const canvas = document.createElement('canvas');
  return canvas.getContext(type);
}

export function getWebGLSummary() {
  try {
    const gl = getContext('webgl2') || getContext('webgl') || getContext('experimental-webgl');
    if (!gl) return { state: 'unavailable', renderer: '', vendor: '', version: '', extensionCount: 0, extensions: [] };

    const debug = gl.getExtension('WEBGL_debug_renderer_info');
    const renderer = debug ? String(gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) || '') : '';
    const vendor = debug ? String(gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) || '') : '';
    const version = String(gl.getParameter(gl.VERSION) || '');
    const shadingLanguageVersion = String(gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || '');
    const extensions = gl.getSupportedExtensions() || [];

    return {
      state: 'ok',
      context: gl instanceof WebGL2RenderingContext ? 'webgl2' : 'webgl1',
      renderer,
      vendor,
      version,
      shadingLanguageVersion,
      extensionCount: extensions.length,
      extensions: extensions.slice(0, 24)
    };
  } catch (error) {
    return {
      state: 'error',
      renderer: '',
      vendor: '',
      version: '',
      extensionCount: 0,
      extensions: [],
      error: String(error)
    };
  }
}

export function webglRendererFamily(summary) {
  const renderer = String(summary?.renderer || '').toLowerCase();
  if (!renderer) return 'none';
  if (renderer.includes('swiftshader')) return 'swiftshader';
  if (renderer.includes('angle')) return 'angle';
  if (renderer.includes('apple')) return 'apple';
  if (renderer.includes('nvidia')) return 'nvidia';
  if (renderer.includes('amd') || renderer.includes('radeon')) return 'amd';
  if (renderer.includes('intel')) return 'intel';
  if (renderer.includes('llvmpipe')) return 'software';
  return 'other';
}
