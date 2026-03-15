import { round } from '../utils/common.js';

async function renderSample(Ctx) {
  const context = new Ctx(1, 44100, 44100);
  const oscillator = context.createOscillator();
  const compressor = context.createDynamicsCompressor();
  oscillator.type = 'triangle';
  oscillator.frequency.value = 1000;
  oscillator.connect(compressor);
  compressor.connect(context.destination);
  oscillator.start(0);

  const buffer = await context.startRendering();
  const data = buffer.getChannelData(0);
  let sum = 0;
  let energy = 0;
  for (let i = 0; i < data.length; i += 128) {
    const abs = Math.abs(data[i]);
    sum += abs;
    energy += abs * abs;
  }

  return {
    sum: round(sum, 8),
    energy: round(energy, 8)
  };
}

export async function audioStabilityProbe() {
  try {
    const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!Ctx) return { state: 'unavailable', stable: true, samples: ['unsupported'] };

    const first = await renderSample(Ctx);
    const second = await renderSample(Ctx);

    const delta = Math.abs(first.sum - second.sum);
    return {
      state: 'ok',
      stable: delta < 0.000001,
      samples: [first.sum, second.sum],
      energy: [first.energy, second.energy],
      delta
    };
  } catch (error) {
    return { state: 'error', stable: true, samples: ['error'], error: String(error) };
  }
}
