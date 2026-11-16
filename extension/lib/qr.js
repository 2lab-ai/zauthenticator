// Image → QR text, using the vendored jsQR build (../vendor/jsQR.js, loaded by popup.html as a
// classic script, which defines globalThis.jsQR). Images are decoded locally from a Blob or a
// data: URL with createImageBitmap (or an <img> on a blob: URL as a fallback) and drawn onto a
// canvas; nothing here touches the network.

// Longest side for the first, cheap pass. Full-size tab screenshots on high-DPI screens are
// several megapixels; a QR code shown on a page is still well resolved after downscaling.
const FIRST_PASS_MAX = 1280;
// Longest side for the full-resolution pass (bounds memory on very large images).
const FULL_PASS_MAX = 4096;
// Images smaller than this also get an upscaled pass: tiny QR images decode more reliably
// when each module covers a few pixels.
const SMALL_IMAGE_MAX = 480;

export class QRError extends Error {
  // code ∈ 'no-qr' | 'bad-image' | 'decoder-missing'
  constructor(code) {
    super(code);
    this.name = 'QRError';
    this.code = code;
  }
}

// source: Blob | File | 'data:image/...' URL string. Resolves to the decoded text of the
// first QR code found; rejects with QRError otherwise.
export async function decodeQR(source) {
  const decoder = globalThis.jsQR;
  if (typeof decoder !== 'function') throw new QRError('decoder-missing');

  const blob = typeof source === 'string' ? blobFromDataUrl(source) : source;
  if (!(blob instanceof Blob)) throw new QRError('bad-image');

  const image = await loadImage(blob);
  try {
    for (const scale of passScales(image.width, image.height)) {
      const width = Math.max(1, Math.round(image.width * scale));
      const height = Math.max(1, Math.round(image.height * scale));
      const text = scan(decoder, image.source, width, height, scale);
      if (text !== null) return text;
    }
  } finally {
    image.close();
  }
  throw new QRError('no-qr');
}

function passScales(width, height) {
  const longest = Math.max(width, height);
  const scales = [];
  if (longest > FIRST_PASS_MAX) scales.push(FIRST_PASS_MAX / longest);
  scales.push(Math.min(1, FULL_PASS_MAX / longest));
  if (longest < SMALL_IMAGE_MAX) scales.push(2);
  return scales;
}

function scan(decoder, source, width, height, scale) {
  const canvas = makeCanvas(width, height);
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  // Transparent pixels read as black; paint white first so a QR on a transparent PNG
  // keeps its light background.
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, width, height);
  // Smooth when shrinking, keep module edges sharp when enlarging.
  ctx.imageSmoothingEnabled = scale < 1;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(source, 0, 0, width, height);
  const { data } = ctx.getImageData(0, 0, width, height);
  const result = decoder(data, width, height, { inversionAttempts: 'attemptBoth' });
  return result && typeof result.data === 'string' && result.data !== '' ? result.data : null;
}

function makeCanvas(width, height) {
  if (typeof OffscreenCanvas === 'function') return new OffscreenCanvas(width, height);
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  return canvas;
}

// Resolves to { source, width, height, close() } where source can be passed to drawImage.
async function loadImage(blob) {
  try {
    const bitmap = await createImageBitmap(blob);
    return { source: bitmap, width: bitmap.width, height: bitmap.height, close: () => bitmap.close() };
  } catch {
    // createImageBitmap rejects some formats (for example SVG); an <img> decodes them.
  }
  const url = URL.createObjectURL(blob);
  try {
    const img = new Image();
    img.src = url;
    await img.decode();
    if (!img.naturalWidth || !img.naturalHeight) throw new QRError('bad-image');
    return { source: img, width: img.naturalWidth, height: img.naturalHeight, close: () => {} };
  } catch {
    throw new QRError('bad-image');
  } finally {
    URL.revokeObjectURL(url);
  }
}

function blobFromDataUrl(url) {
  const match = /^data:([^;,]*)((?:;[^;,]*)*?),(.*)$/s.exec(url);
  if (!match) throw new QRError('bad-image');
  const type = match[1] || 'application/octet-stream';
  const isBase64 = /;base64$/i.test(match[2]);
  let bytes;
  try {
    if (isBase64) {
      const binary = atob(match[3]);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    } else {
      bytes = new TextEncoder().encode(decodeURIComponent(match[3]));
    }
  } catch {
    throw new QRError('bad-image');
  }
  return new Blob([bytes], { type });
}
