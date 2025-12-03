// Our custom chunked file encryption helpers (AES-256-GCM, 1MB chunks).
// Different naming than message encryption so we can spot mistakes quickly.

import {
  AES_GCM_ALGO,
  AES_KEY_LENGTH,
  IV_LENGTH_BYTES,
  TAG_LENGTH_BITS,
  TAG_LENGTH_BYTES,
} from './constants';
import { getRandomBytes } from './random';
import { bytesToBase64, base64ToBytes } from './messageFormat';
import { encryptMessage, decryptMessage, packPayload, unpackPayload } from './aesGcm';

const crypto_api = globalThis.crypto;

if (!crypto_api || !crypto_api.subtle) {
  throw new Error('Web Crypto API (crypto.subtle) not found - cannot do file encryption');
}

export const FILE_CHUNK_SIZE = 1024 * 1024; // 1 MB

const textEncoder = new TextEncoder();

async function importFileKey(rawKeyBytes) {
  if (!(rawKeyBytes instanceof Uint8Array)) {
    throw new TypeError('sessionKey must be Uint8Array for file encryption');
  }
  return crypto_api.subtle.importKey(
    'raw',
    rawKeyBytes,
    { name: AES_GCM_ALGO, length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Split a file buffer into 1MB Uint8Array chunks.
 */
export function splitIntoChunks(arrayBuffer, chunkSize = FILE_CHUNK_SIZE) {
  const allBytes = arrayBuffer instanceof Uint8Array ? arrayBuffer : new Uint8Array(arrayBuffer);
  const chunks = [];
  for (let offset = 0; offset < allBytes.byteLength; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, allBytes.byteLength);
    const chunkData = allBytes.slice(offset, end);
    chunks.push(chunkData);
  }
  return chunks;
}

/**
 * Encrypt a raw chunk of bytes with AES-256-GCM. Fresh IV per chunk.
 */
export async function encryptFileChunk(chunkData, sessionKeyBytes, chunkIndex, totalChunks) {
  const iv_buf = getRandomBytes(IV_LENGTH_BYTES); // 12-byte IV each time
  console.log(`Encrypting chunk ${chunkIndex + 1}/${totalChunks}...`);

  const key = await importFileKey(sessionKeyBytes);
  const algo = { name: AES_GCM_ALGO, iv: iv_buf, tagLength: TAG_LENGTH_BITS };

  const encryptedBuffer = await crypto_api.subtle.encrypt(algo, key, chunkData);
  const encryptedBlob = new Uint8Array(encryptedBuffer);
  const tag = encryptedBlob.slice(encryptedBlob.length - TAG_LENGTH_BYTES);
  const ciphertext = encryptedBlob.slice(0, encryptedBlob.length - TAG_LENGTH_BYTES);

  return { ciphertext, iv: iv_buf, tag };
}

/**
 * Decrypt a chunk back to raw bytes.
 */
export async function decryptFileChunk(ciphertext, iv, tag, sessionKeyBytes) {
  const key = await importFileKey(sessionKeyBytes);
  const ctBytes = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);
  const ivBytes = iv instanceof Uint8Array ? iv : new Uint8Array(iv);
  const tagBytes = tag instanceof Uint8Array ? tag : new Uint8Array(tag);

  const combined = new Uint8Array(ctBytes.byteLength + tagBytes.byteLength);
  combined.set(ctBytes, 0);
  combined.set(tagBytes, ctBytes.byteLength);

  const algo = { name: AES_GCM_ALGO, iv: ivBytes, tagLength: TAG_LENGTH_BITS };
  const decrypted = await crypto_api.subtle.decrypt(algo, key, combined);
  return new Uint8Array(decrypted);
}

/**
 * Merge decrypted chunks back into a single Uint8Array.
 * TODO: add file integrity HMAC after all chunks received
 */
export function combineChunks(chunks) {
  const totalLength = chunks.reduce((sum, c) => sum + c.byteLength, 0);
  const merged = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of chunks) {
    merged.set(part, offset);
    offset += part.byteLength;
  }
  return merged;
}

/**
 * Encrypt filename once (as text) so we do not leak it with each chunk.
 */
export async function encryptFilename(filename, sessionKeyBytes) {
  const encrypted = await encryptMessage(filename || 'unknown', sessionKeyBytes);
  const packed = packPayload(encrypted.ciphertext, encrypted.iv, encrypted.tag);
  return bytesToBase64(packed);
}

export async function decryptFilename(filenameB64, sessionKeyBytes) {
  const payloadBytes = base64ToBytes(filenameB64);
  const unpacked = unpackPayload(payloadBytes);
  const key = sessionKeyBytes; // reuse type name to make it obvious
  return decryptMessage(unpacked.ciphertext, unpacked.iv, unpacked.tag, key);
}

/**
 * Utility to base64-encode a chunk triple for transport.
 */
export function serializeEncryptedChunk({ ciphertext, iv, tag }) {
  return {
    ciphertext: bytesToBase64(ciphertext),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(tag),
  };
}

export function deserializeEncryptedChunk(serialized) {
  return {
    ciphertext: base64ToBytes(serialized.ciphertext),
    iv: base64ToBytes(serialized.iv),
    tag: base64ToBytes(serialized.tag),
  };
}
