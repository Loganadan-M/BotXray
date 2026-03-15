import { hashString, round } from '../utils/common.js';

function drawCanvas(ctx, label) {
  ctx.clearRect(0, 0, 300, 120);
  ctx.textBaseline = 'top';
  ctx.fillStyle = '#f60';
  ctx.fillRect(10, 8, 120, 30);
  ctx.fillStyle = '#069';
  ctx.font = '16px Arial';
  ctx.fillText(label, 14, 46);
  ctx.fillStyle = 'rgba(120, 0, 255, 0.45)';
  ctx.beginPath();
  ctx.arc(180, 52, 26, 0, Math.PI * 2);
  ctx.fill();
}

function pixelSample(ctx) {
  const image = ctx.getImageData(0, 0, 300, 120).data;
  let acc = 0;
  for (let i = 0; i < image.length; i += 64) {
    acc += image[i] + image[i + 1] + image[i + 2] + image[i + 3];
  }
  return round(acc / 1000, 4);
}

export function canvasStabilityProbe(iterations = 4) {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 300;
    canvas.height = 120;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) {
      return { state: 'unavailable', stable: true, hashes: ['2d-context-unavailable'] };
    }

    const hashes = [];
    const samples = [];
    for (let i = 0; i < iterations; i += 1) {
      drawCanvas(ctx, `detector-canvas-${i % 2}`);
      hashes.push(hashString(canvas.toDataURL()));
      samples.push(pixelSample(ctx));
    }

    return {
      state: 'ok',
      stable: hashes.every(hash => hash === hashes[0]),
      hash: hashes[0],
      hashes,
      samples
    };
  } catch (error) {
    return { state: 'error', stable: true, hashes: ['error'], error: String(error) };
  }
}

export async function offscreenCanvasProbe() {
  try {
    if (typeof OffscreenCanvas === 'undefined') {
      return { state: 'unavailable', stable: true, hashes: ['unsupported'] };
    }

    const hashes = [];
    for (let i = 0; i < 3; i += 1) {
      const canvas = new OffscreenCanvas(300, 120);
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) return { state: 'unavailable', stable: true, hashes: ['2d-context-unavailable'] };
      drawCanvas(ctx, `offscreen-detector-${i % 2}`);

      if (typeof canvas.convertToBlob === 'function') {
        const blob = await canvas.convertToBlob();
        const buffer = await blob.arrayBuffer();
        hashes.push(hashString(String(buffer.byteLength) + ':' + hashString(new Uint8Array(buffer).slice(0, 2048).join(','))));
      } else {
        const image = ctx.getImageData(0, 0, 300, 120).data;
        hashes.push(hashString(Array.from(image.slice(0, 600)).join(',')));
      }
    }

    return {
      state: 'ok',
      stable: hashes.every(hash => hash === hashes[0]),
      hash: hashes[0],
      hashes
    };
  } catch (error) {
    return { state: 'error', stable: true, hashes: ['error'], error: String(error) };
  }
}
