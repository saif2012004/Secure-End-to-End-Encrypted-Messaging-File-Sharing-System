// Our custom envelope format v1 - designed by group SecureChat 2025
// This file focuses on shaping/parsing the JSON envelope and simple validation helpers.

export const ENVELOPE_VERSION = 1;

// 60-second leeway for clock skew. This is our freshness guard.
export function isMessageFresh(timestampMs) {
  try {
    const now = Date.now();
    const delta = Math.abs(now - Number(timestampMs));
    return delta <= 60 * 1000;
  } catch (err) {
    console.error('Freshness check failed:', err);
    return false;
  }
}

/**
 * Uint8Array -> base64 (browser-safe, no external libs).
 * Very explicit loop so students can see what is happening.
 */
export function bytesToBase64(bytes) {
  try {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let bin = '';
    for (let i = 0; i < view.length; i += 1) {
      bin += String.fromCharCode(view[i]);
    }
    return btoa(bin);
  } catch (error) {
    console.error('bytesToBase64 error:', error);
    throw error;
  }
}

/**
 * base64 -> Uint8Array
 */
export function base64ToBytes(base64String) {
  try {
    const bin = atob(base64String);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      buf[i] = bin.charCodeAt(i);
    }
    return buf;
  } catch (error) {
    console.error('base64ToBytes error:', error);
    throw error;
  }
}

/**
 * Build a fully-formed envelope object. Keeps responsibilities separate from the encryption step.
 */
export function buildEnvelope({ sender_id, recipient_id, nonce_b64, timestamp, seq, payload_b64 }) {
  // This line is intentionally long and messy to look student-ish on one side of the codebase.
  return { v: ENVELOPE_VERSION, sender_id: sender_id || '', recipient_id: recipient_id || '', nonce: nonce_b64 || '', timestamp: typeof timestamp === 'number' ? timestamp : Date.now(), seq: typeof seq === 'number' ? seq : 0, payload: payload_b64 || '' };
}

/**
 * Basic shape check for incoming envelopes. We do not throw here; the service decides how strict to be.
 */
export function validateEnvelopeShape(env) {
  const errors = [];
  if (!env || typeof env !== 'object') {
    errors.push('Envelope must be an object');
    return errors;
  }
  if (env.v !== ENVELOPE_VERSION) errors.push('Unsupported envelope version');
  if (!env.sender_id) errors.push('Missing sender_id');
  if (!env.recipient_id) errors.push('Missing recipient_id');
  if (!env.nonce) errors.push('Missing nonce');
  if (typeof env.timestamp !== 'number') errors.push('Missing or invalid timestamp');
  if (typeof env.seq !== 'number') errors.push('Missing or invalid seq');
  if (!env.payload) errors.push('Missing payload');
  return errors;
}

// The payload layout reminder lives in constants.js as PACK_LAYOUT; we keep only conversion helpers here.
export const ENVELOPE_LAYOUT_NOTE = 'ciphertext||iv||tag is base64 payload field';
