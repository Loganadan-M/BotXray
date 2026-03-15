import { hashString, round } from '../utils/common.js';

const CANDIDATE_FONTS = [
  'Arial',
  'Helvetica',
  'Times New Roman',
  'Courier New',
  'Verdana',
  'Georgia',
  'Trebuchet MS',
  'Monaco'
];

export function textMetricsProbe() {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 540;
    canvas.height = 120;
    const ctx = canvas.getContext('2d');
    if (!ctx) return { state: 'unavailable', stable: true, metrics: [], fontPresence: {}, hash: '' };

    const phrase = 'Sphinx of black quartz, judge my vow 12345';

    const measureSet = () => CANDIDATE_FONTS.map(font => {
      ctx.font = `16px '${font}', monospace`;
      const metrics = ctx.measureText(phrase);
      return {
        font,
        width: round(metrics.width, 4),
        actualBoundingBoxAscent: round(metrics.actualBoundingBoxAscent || 0, 4),
        actualBoundingBoxDescent: round(metrics.actualBoundingBoxDescent || 0, 4)
      };
    });

    const a = measureSet();
    const b = measureSet();
    const aHash = hashString(JSON.stringify(a));
    const bHash = hashString(JSON.stringify(b));

    const baselineWidths = {};
    a.forEach(item => {
      baselineWidths[item.font] = item.width;
    });

    return {
      state: 'ok',
      stable: aHash === bHash,
      hash: aHash,
      metrics: a,
      secondHash: bHash,
      fontPresence: baselineWidths
    };
  } catch (error) {
    return {
      state: 'error',
      stable: true,
      metrics: [],
      fontPresence: {},
      hash: '',
      error: String(error)
    };
  }
}

export function suspiciousFontProfile(probeResult) {
  const values = Object.values(probeResult?.fontPresence || {});
  if (values.length < 3) return false;
  const unique = new Set(values.map(value => String(value)));
  return unique.size <= 2;
}
