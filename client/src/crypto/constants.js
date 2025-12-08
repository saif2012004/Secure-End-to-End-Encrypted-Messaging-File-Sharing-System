// Tiny constants module so we don't sprinkle "magic numbers" everywhere
// Everything here is intentionally verbose so future us (and our prof) can read it fast.

// Algorithm name exactly as Web Crypto expects it.
export const AES_GCM_ALGO = 'AES-GCM';

// Key + IV + tag sizes for AES-256-GCM (tag is 128-bit by default in browsers).
export const AES_KEY_LENGTH = 256; // bits, so 32 bytes
export const IV_LENGTH_BYTES = 12; // 96-bit IV is the NIST recommendation
export const TAG_LENGTH_BITS = 128; // Web Crypto uses bits for tagLength
export const TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8; // 16-byte auth tag

// Extra helpers for the random util
export const NONCE_LENGTH_BYTES = 16; // 128-bit app-level nonce (separate from IV)

// Encoding used when we turn strings into bytes and back
export const TEXT_ENCODING = 'utf-8';

// Helpful reminder for pack/unpack layout
export const PACK_LAYOUT = 'ciphertext||iv||tag';
