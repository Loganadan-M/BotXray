import { hashString } from '../utils/common.js';

export function clientRectsStabilityProbe() {
  try {
    const node = document.createElement('div');
    node.textContent = 'detector-client-rect-probe';
    node.style.position = 'absolute';
    node.style.left = '-9999px';
    node.style.top = '-9999px';
    node.style.fontFamily = 'Arial, sans-serif';
    node.style.fontSize = '16px';
    node.style.whiteSpace = 'nowrap';
    document.body.appendChild(node);

    const rects = [];
    for (let i = 0; i < 8; i += 1) {
      const rect = node.getBoundingClientRect();
      rects.push(`${rect.x.toFixed(4)}|${rect.y.toFixed(4)}|${rect.width.toFixed(4)}|${rect.height.toFixed(4)}`);
    }

    document.body.removeChild(node);
    return {
      state: 'ok',
      stable: rects.every(value => value === rects[0]),
      rects,
      hash: hashString(rects.join('|'))
    };
  } catch (error) {
    return {
      state: 'error',
      stable: true,
      rects: ['error'],
      error: String(error)
    };
  }
}
