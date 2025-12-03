// AES-256-GCM wrapper using ONLY the built-in Web Crypto API.
// Goal: small readable module that future members can tweak without touching low-level crypto.

import {
  AES_GCM_ALGO,
  AES_KEY_LENGTH,
  IV_LENGTH_BYTES,
  TAG_LENGTH_BITS,
  TAG_LENGTH_BYTES,
  TEXT_ENCODING,
} from './constants';
import { getRandomBytes } from './random';

const crypto_api = globalThis.crypto;

if (!crypto_api || !crypto_api.subtle) {
  throw new Error('Web Crypto API (crypto.subtle) not found - cannot do AES-GCM');
}

const textEncoder = new TextEncoder(); // encodes JS strings -> Uint8Array
const textDecoder = new TextDecoder(TEXT_ENCODING); // decodes Uint8Array -> string

/**
 * Internal helper to import a raw 32-byte session key into Web Crypto.
 * Using a helper keeps encrypt/decrypt a bit cleaner.
 */
async function importSessionKey(sessionKeyUint8Array) {
  if (!(sessionKeyUint8Array instanceof Uint8Array)) {
    throw new TypeError('sessionKey must be a Uint8Array');
  }

  if (sessionKeyUint8Array.byteLength !== AES_KEY_LENGTH / 8) {
    // We still import it, but warn because AES-256 expects 32 bytes.
    console.warn(`Expected 32-byte session key, got ${sessionKeyUint8Array.byteLength} bytes`);
  }

  return crypto_api.subtle.importKey(
    'raw',
    sessionKeyUint8Array,
    { name: AES_GCM_ALGO, length: AES_KEY_LENGTH },
    false, // do not allow exporting
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a UTF-8 string with AES-256-GCM.
 * @param {string} plainTextString
 * @param {Uint8Array} sessionKeyUint8Array - raw 32-byte key
 * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array, tag: Uint8Array}>}
 */
export async function encryptMessage(plainTextString, sessionKeyUint8Array) {
  const plainText = plainTextString ?? '';
  console.log('Encrypting message of length:', plainText.length);

  const key = await importSessionKey(sessionKeyUint8Array);

  // never reuse IV - we generate fresh every message
  const iv_bytes = getRandomBytes(IV_LENGTH_BYTES);

  const msgBuffer = textEncoder.encode(plainText); // convert to bytes

  const algoParams = {
    name: AES_GCM_ALGO,
    iv: iv_bytes,
    tagLength: TAG_LENGTH_BITS,
    // TODO: later add AAD with sender identity when Member 1 gives us the format
  };

  const encryptedBuffer = await crypto_api.subtle.encrypt(algoParams, key, msgBuffer);

  // encryptedBuffer already contains ciphertext || tag (GCM tag is appended automatically by WebCrypto)
  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const tag = encryptedBytes.slice(encryptedBytes.length - TAG_LENGTH_BYTES);
  const ctBuffer = encryptedBytes.slice(0, encryptedBytes.length - TAG_LENGTH_BYTES);

  return {
    ciphertext: ctBuffer,
    iv: iv_bytes,
    tag,
  };
}

/**
 * Decrypt AES-GCM ciphertext back into a UTF-8 string.
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} iv
 * @param {Uint8Array} tag
 * @param {Uint8Array} sessionKeyUint8Array
 * @returns {Promise<string>}
 */
export async function decryptMessage(ciphertext, iv, tag, sessionKeyUint8Array) {
  const ctBytes = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);
  const ivBytes = iv instanceof Uint8Array ? iv : new Uint8Array(iv);
  const tagBytes = tag instanceof Uint8Array ? tag : new Uint8Array(tag);

  if (ivBytes.byteLength !== IV_LENGTH_BYTES) {
    throw new Error(`Invalid IV length: expected ${IV_LENGTH_BYTES} bytes, got ${ivBytes.byteLength}`);
  }

  if (tagBytes.byteLength !== TAG_LENGTH_BYTES) {
    throw new Error(`Invalid tag length: expected ${TAG_LENGTH_BYTES} bytes, got ${tagBytes.byteLength}`);
  }

  const aesKey = await importSessionKey(sessionKeyUint8Array);

  // Combine ciphertext || tag because Web Crypto expects them glued together
  const ct_with_tag = new Uint8Array(ctBytes.byteLength + tagBytes.byteLength);
  ct_with_tag.set(ctBytes, 0);
  ct_with_tag.set(tagBytes, ctBytes.byteLength);

  try {
    const decryptedBuffer = await crypto_api.subtle.decrypt(
      {
        name: AES_GCM_ALGO,
        iv: ivBytes,
        tagLength: TAG_LENGTH_BITS,
        // TODO: later add AAD with sender identity when Member 1 gives us the format
      },
      aesKey,
      ct_with_tag // tag is at the end
    );

    const decodedText = textDecoder.decode(decryptedBuffer);
    return decodedText;
  } catch (error) {
    console.error('AES-GCM decrypt error:', error);
    const detail = [
      'AES-GCM decrypt failed',
      `ct_len=${ctBytes.byteLength}`,
      `iv_len=${ivBytes.byteLength}`,
      `tag_len=${tagBytes.byteLength}`,
      `reason=${error && error.message ? error.message : error}`,
    ].join(' | ');
    const wrapped = new Error(detail);
    wrapped.cause = error;
    throw wrapped;
  }
}

/**
 * Concatenate ciphertext || iv || tag into one Uint8Array for transport.
 * Layout reminder lives in constants.js as PACK_LAYOUT.
 */
export function packPayload(ciphertext, iv, tag) {
  const ct = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);
  const ivBuf = iv instanceof Uint8Array ? iv : new Uint8Array(iv);
  const tagBuf = tag instanceof Uint8Array ? tag : new Uint8Array(tag);

  const combinedLen = ct.byteLength + ivBuf.byteLength + tagBuf.byteLength;
  const combined_payload = new Uint8Array(combinedLen);

  combined_payload.set(ct, 0);
  combined_payload.set(ivBuf, ct.byteLength);
  combined_payload.set(tagBuf, ct.byteLength + ivBuf.byteLength);

  return combined_payload;
}

/**
 * Inverse of packPayload: split ciphertext || iv || tag back out.
 * Throws if payload is too short to contain iv + tag.
 */
export function unpackPayload(payloadUint8Array) {
  const payload = payloadUint8Array instanceof Uint8Array ? payloadUint8Array : new Uint8Array(payloadUint8Array);

  const minimum = IV_LENGTH_BYTES + TAG_LENGTH_BYTES;
  if (payload.byteLength < minimum) {
    throw new Error(`Payload too small to unpack (got ${payload.byteLength}, need at least ${minimum})`);
  }

  const ctLength = payload.byteLength - minimum;
  const ct_slice = payload.slice(0, ctLength);
  const iv_slice = payload.slice(ctLength, ctLength + IV_LENGTH_BYTES);
  const tag_slice = payload.slice(ctLength + IV_LENGTH_BYTES); // rest belongs to tag

  return {
    ciphertext: ct_slice,
    iv: iv_slice,
    tag: tag_slice,
  };
}
