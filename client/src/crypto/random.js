// Random helpers powered by the Web Crypto API (no external libs allowed).
// These are small wrappers so teammates don't accidentally reach for Math.random().

import { NONCE_LENGTH_BYTES } from './constants';

const crypto_api = globalThis.crypto;

if (!crypto_api || !crypto_api.getRandomValues) {
  // Bail out early if someone tries to run this without a proper Web Crypto impl.
  throw new Error('Web Crypto API is missing; cannot generate secure randomness');
}

/**
 * Get cryptographically strong random bytes.
 * @param {number} length - number of bytes we want
 * @returns {Uint8Array}
 */
export function getRandomBytes(length) {
  if (typeof length !== 'number' || length <= 0) {
    throw new TypeError('length must be a positive number of bytes');
  }

  const byte_array = new Uint8Array(length);
  crypto_api.getRandomValues(byte_array); // This uses the OS CSPRNG under the hood.
  return byte_array;
}

/**
 * 16-byte nonce helper (different from the AES-GCM IV we use per message).
 * Could be useful for app-level replay protection or session identifiers.
 */
export function getRandomNonce() {
  return getRandomBytes(NONCE_LENGTH_BYTES);
}

// Simple incrementing sequence number. Not meant to be secret, just ordering.
let seq_counter = 0;

/**
 * Returns a monotonically increasing sequence number.
 * Useful for logging, message ordering, or deriving counters.
 */
export function getSeqNumber() {
  seq_counter = (seq_counter + 1) >>> 0; // keep it in uint32 space
  return seq_counter;
}
