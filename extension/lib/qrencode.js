// Text → QR code modules, using the vendored qrcode-generator build (../vendor/qrcode.js, loaded
// by popup.html as a classic script, which defines globalThis.qrcode). No DOM and no canvas here:
// the caller draws the modules and adds the 4-module light margin (quiet zone) around them.
//
// The text is written in byte mode as UTF-8. qrcode-generator turns text into bytes with its
// global qrcode.stringToBytes, which by default keeps only the low 8 bits of each UTF-16 unit
// (Latin-1), so non-ASCII text would be garbled. Rather than change that global for every other
// user, encodeQR sets it to return this text's UTF-8 bytes for its one addData call and puts the
// previous function back straight after.

// Most bytes one QR code holds (version 40, byte mode), per error correction level.
const MAX_BYTES = { L: 2953, M: 2331, Q: 1663, H: 1273 };

export class QREncodeError extends Error {
  // code ∈ 'too-long' | 'encoder-missing'
  constructor(code) {
    super(code);
    this.name = 'QREncodeError';
    this.code = code;
  }
}

/**
 * Encode text as a QR code of the smallest version that holds it.
 *
 * @param {string} text
 * @param {{ecc?: 'L'|'M'|'Q'|'H'}} [options] error correction level, default 'M'
 * @returns {{size: number, modules: Uint8Array}} size × size modules, row by row, 1 = dark;
 *   no quiet zone
 * @throws {QREncodeError} 'encoder-missing' when globalThis.qrcode is not loaded, 'too-long' when
 *   the text does not fit a version 40 code at this level
 */
export function encodeQR(text, { ecc = 'M' } = {}) {
  if (typeof text !== 'string') throw new TypeError('QR text must be a string');
  if (typeof ecc !== 'string' || !Object.hasOwn(MAX_BYTES, ecc)) {
    throw new TypeError(`Unknown error correction level: ${ecc}`);
  }
  const qrcode = globalThis.qrcode;
  if (typeof qrcode !== 'function') throw new QREncodeError('encoder-missing');

  const bytes = Array.from(new TextEncoder().encode(text));
  // Checked before make(), which would otherwise try every version up to 40 first.
  if (bytes.length > MAX_BYTES[ecc]) throw new QREncodeError('too-long');

  const qr = qrcode(0, ecc); // type number 0: the smallest version that holds the data
  const previous = qrcode.stringToBytes;
  qrcode.stringToBytes = () => bytes;
  try {
    qr.addData(text, 'Byte'); // reads the bytes now, through qrcode.stringToBytes
  } finally {
    qrcode.stringToBytes = previous;
  }
  try {
    qr.make();
  } catch (err) {
    // qrcode-generator throws plain strings; this one means the data did not fit version 40.
    if (typeof err === 'string' && err.startsWith('code length overflow')) throw new QREncodeError('too-long');
    throw err;
  }

  const size = qr.getModuleCount();
  const modules = new Uint8Array(size * size);
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) modules[row * size + col] = qr.isDark(row, col) ? 1 : 0;
  }
  return { size, modules };
}
