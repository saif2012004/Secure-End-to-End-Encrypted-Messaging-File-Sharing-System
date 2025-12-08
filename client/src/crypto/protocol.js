// Our custom protocol – SecureChat Initial Handshake v1.2
// This file defines the message shapes and low-level helpers for the
// "SecureChat Double-Ratchet-Style Initial Handshake v1" variant. The goal is
// intentionally educational: it mirrors double-ratchet ideas (ephemeral keys +
// identity authentication) but reorders inputs to make it feel student-invented
// while still defending against MITM when the identity keys are trusted.

export const PROTOCOL_NAME = 'SecureChat Double-Ratchet-Style Initial Handshake v1';
export const PROTOCOL_VERSION = '1.2';

export const MESSAGE_TYPES = Object.freeze({
  KE_INIT: 'KE_INIT',
  KE_REPLY: 'KE_REPLY',
  KEY_CONFIRM: 'KEY_CONFIRM',
});

// Allow a narrow clock skew to reject stale or replayed packets.
export const MAX_CLOCK_SKEW_MS = 30 * 1000; // ±30 seconds
export const HKDF_INFO = 'SecureChatSessionV1';
export const ZERO_SALT = new Uint8Array(32); // explicit all-zero salt

// secp256r1 / P-256 parameters for manual point compression/decompression.
const P256_P = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const P256_A = (P256_P - 3n); // curve coefficient a = -3 mod p
const P256_B = BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');

// ---------- Encoding helpers ----------
export function concatUint8(...parts) {
  const total = parts.reduce((sum, p) => sum + p.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(new Uint8Array(p), offset);
    offset += p.byteLength;
  }
  return out;
}

export function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function encodeTimestampSeconds(tsSeconds) {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(tsSeconds), false);
  return new Uint8Array(view.buffer);
}

export function isTimestampFresh(tsSeconds, nowMs = Date.now()) {
  const skew = Math.abs(nowMs - tsSeconds * 1000);
  return skew <= MAX_CLOCK_SKEW_MS;
}

// ---------- P-256 point compression utilities ----------
function mod(n, m) {
  const result = n % m;
  return result >= 0n ? result : result + m;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = mod(base, modulus);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = mod(result * b, modulus);
    }
    e >>= 1n;
    b = mod(b * b, modulus);
  }
  return result;
}

function bufferToBigInt(bytes) {
  let out = 0n;
  for (const byte of bytes) {
    out = (out << 8n) + BigInt(byte);
  }
  return out;
}

function bigIntToBuffer(num, length = 32) {
  const out = new Uint8Array(length);
  let temp = num;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return out;
}

// Convert a raw uncompressed 65-byte P-256 point into a 33-byte compressed form.
export function compressP256Public(rawUncompressed) {
  if (!(rawUncompressed instanceof ArrayBuffer || ArrayBuffer.isView(rawUncompressed))) {
    throw new Error('compressP256Public expects an ArrayBuffer or view');
  }
  const bytes = new Uint8Array(rawUncompressed);
  if (bytes.byteLength !== 65 || bytes[0] !== 0x04) {
    throw new Error('Invalid uncompressed P-256 key');
  }
  const x = bytes.slice(1, 33);
  const y = bytes.slice(33, 65);
  const yIsOdd = (y[y.length - 1] & 1) === 1;
  const prefix = yIsOdd ? 0x03 : 0x02;
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(x, 1);
  return out.buffer;
}

// Decompress a 33-byte compressed P-256 point into the raw 65-byte uncompressed form.
export function decompressP256Public(compressed) {
  if (!(compressed instanceof ArrayBuffer || ArrayBuffer.isView(compressed))) {
    throw new Error('decompressP256Public expects an ArrayBuffer or view');
  }
  const bytes = new Uint8Array(compressed);
  if (bytes.byteLength !== 33) {
    throw new Error('Invalid compressed P-256 key length');
  }
  const prefix = bytes[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error('Invalid compressed key prefix');
  }
  const xBytes = bytes.slice(1);
  const x = bufferToBigInt(xBytes);

  // y^2 = x^3 + ax + b (mod p)
  const rhs = mod(
    mod(mod(x * x, P256_P) * x, P256_P) +
      mod(P256_A * x, P256_P) +
      P256_B,
    P256_P,
  );
  // For P-256, p % 4 === 3, so we can use y = rhs^((p+1)/4) mod p
  const yCandidate = modPow(rhs, (P256_P + 1n) >> 2n, P256_P);
  const yIsOdd = (yCandidate & 1n) === 1n;
  const shouldBeOdd = prefix === 0x03;
  const y = (yIsOdd === shouldBeOdd) ? yCandidate : mod(P256_P - yCandidate, P256_P);

  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(xBytes, 1);
  uncompressed.set(bigIntToBuffer(y), 33);
  return uncompressed.buffer;
}
