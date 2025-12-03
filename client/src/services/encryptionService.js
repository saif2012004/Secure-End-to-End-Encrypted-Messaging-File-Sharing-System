// Our custom envelope format v1 - designed by group SecureChat 2025
// This service glues AES-GCM, base64 packing, and replay protection storage.

import { encryptMessage, decryptMessage, packPayload, unpackPayload } from '../crypto/aesGcm';
import { getRandomNonce, getSeqNumber } from '../crypto/random';
import { buildEnvelope, bytesToBase64, base64ToBytes, isMessageFresh, validateEnvelopeShape } from '../crypto/messageFormat';
import { logEvent } from './loggingService';

const STORE_NAME = 'replay_protection';
const DB_NAME = 'securechat_replay_db';
const DB_VERSION = 1;

const idb = globalThis.indexedDB;

function openReplayDb() {
  if (!idb) {
    throw new Error('IndexedDB not available - cannot enforce replay protection');
  }

  return new Promise((resolve, reject) => {
    const req = idb.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (ev) => {
      const db = ev.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('Failed to open IndexedDB for replay_protection'));
  });
}

async function withStore(mode, fn) {
  const db = await openReplayDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const store = tx.objectStore(STORE_NAME);
    let finished = false;
    tx.oncomplete = () => {
      if (!finished) finished = true, resolve();
    };
    tx.onerror = () => {
      if (!finished) finished = true, reject(tx.error || new Error('IndexedDB tx failed'));
    };
    try {
      const result = fn(store);
      // If fn returns a promise, wait for it; otherwise resolve immediately.
      Promise.resolve(result).then((val) => {
        if (!finished) finished = true, resolve(val);
      }).catch((err) => {
        if (!finished) finished = true, reject(err);
      });
    } catch (err) {
      if (!finished) finished = true, reject(err);
    }
  });
}

async function loadReplayRecord(key) {
  return withStore('readonly', (store) => new Promise((resolve, reject) => {
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error || new Error('Failed to load replay record'));
  }));
}

async function saveReplayRecord(record) {
  return withStore('readwrite', (store) => new Promise((resolve, reject) => {
    const req = store.put(record);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error || new Error('Failed to save replay record'));
  }));
}

// Clear stored nonce/seq for a given user (e.g., after a new session key)
export async function clearReplayState(replayKey) {
  if (!replayKey) return;
  return withStore('readwrite', (store) => new Promise((resolve, reject) => {
    const req = store.delete(replayKey);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error || new Error('Failed to clear replay record'));
  }));
}

/**
 * Create an outbound envelope with encryption and packing.
 */
export async function createEncryptedEnvelope(
  plainText,
  sessionKeyUint8,
  targetUserId,
  myIdentityPub,
  seqOverride,
) {
  try {
    const nonceBytes = getRandomNonce(); // 16-byte nonce for replay protection (not the AES IV)
    const nonce_b64 = bytesToBase64(nonceBytes);
    const seq_num = typeof seqOverride === 'number' ? seqOverride : getSeqNumber();

    const encrypted = await encryptMessage(plainText, sessionKeyUint8);
    const packed = packPayload(encrypted.ciphertext, encrypted.iv, encrypted.tag);
    const payload_b64 = bytesToBase64(packed); // payload is ciphertext||iv||tag

    const envelope = buildEnvelope({
      sender_id: myIdentityPub,
      recipient_id: targetUserId,
      nonce_b64,
      timestamp: Date.now(),
      seq: seq_num,
      payload_b64,
    });

    return envelope;
  } catch (err) {
    console.error('Failed to create envelope:', err);
    const wrapped = new Error(`createEncryptedEnvelope failed: ${err.message || err}`);
    wrapped.cause = err;
    throw wrapped;
  }
}

/**
 * Verify replay protections, then decrypt.
 */
export async function parseAndDecryptEnvelope(envelopeJson, sessionKeyUint8, replayScope) {
  let env;
  try {
    env = typeof envelopeJson === 'string' ? JSON.parse(envelopeJson) : envelopeJson;
  } catch (err) {
    const msg = `Invalid envelope JSON: ${err.message}`;
    logEvent('decrypt_error', { reason: msg });
    throw new Error(msg);
  }

  const validationErrors = validateEnvelopeShape(env);
  if (validationErrors.length) {
    const msg = `Envelope validation failed: ${validationErrors.join('; ')}`;
    logEvent('decrypt_error', { sender: env?.sender_id, reason: msg });
    throw new Error(msg);
  }

  if (!isMessageFresh(env.timestamp)) {
    console.warn('Dropping stale/suspicious message timestamp', env.timestamp, 'now:', Date.now());
    logEvent('replay_detected', { sender: env.sender_id, nonce: env.nonce, seq: env.seq, reason: 'stale_timestamp' });
    throw new Error('REPLAY_ATTACK_DETECTED');
  }

  const replayKey = replayScope || env.sender_id;
  const senderId = replayKey;
  const nonce_b64 = env.nonce;

  let replayRecord = null;
  try {
    replayRecord = await loadReplayRecord(replayKey);
  } catch (err) {
    console.error('Replay record load failed:', err);
    // We still proceed but keep a note. If storage is unavailable we cannot enforce replay protections fully.
  }

  const lastSeq = replayRecord && typeof replayRecord.lastSeq === 'number' ? replayRecord.lastSeq : 0;
  const seenNonces = replayRecord && Array.isArray(replayRecord.nonces) ? replayRecord.nonces : [];

  if (seenNonces.includes(nonce_b64)) {
    console.error('Replay nonce detected for sender:', senderId, 'nonce:', nonce_b64);
    logEvent('replay_detected', { sender: senderId, nonce: nonce_b64, seq: env.seq, reason: 'nonce_reuse' });
    throw new Error('REPLAY_ATTACK_DETECTED');
  }

  if (env.seq <= lastSeq) {
    console.error(`Replay seq detected for sender ${senderId}: incoming ${env.seq} <= stored ${lastSeq}`);
    logEvent('replay_detected', { sender: senderId, nonce: nonce_b64, seq: env.seq, lastSeq, reason: 'seq_reuse' });
    throw new Error('REPLAY_ATTACK_DETECTED');
  }

  let plaintext = '';
  try {
    const payloadBytes = base64ToBytes(env.payload);
    const split = unpackPayload(payloadBytes);
    plaintext = await decryptMessage(split.ciphertext, split.iv, split.tag, sessionKeyUint8);
  } catch (err) {
    const wrapped = new Error(`Decrypt failed: ${err.message || err}`);
    wrapped.cause = err;
    logEvent('decrypt_error', { sender: senderId, nonce: nonce_b64, seq: env.seq, reason: err.message || String(err) });
    throw wrapped;
  }

  // Only persist replay info after successful decryption.
  try {
    const updatedNonces = [...seenNonces, nonce_b64];
    // keep last 200 nonces to avoid unbounded growth
    const cappedNonces = updatedNonces.length > 200 ? updatedNonces.slice(updatedNonces.length - 200) : updatedNonces;
    await saveReplayRecord({
      id: replayKey,
      lastSeq: env.seq,
      nonces: cappedNonces,
    });
  } catch (err) {
    console.warn('Could not persist replay info (will still return plaintext):', err);
  }

  return plaintext;
}

/**
 * Weak decrypt for replay attack demo - intentionally skips replay checks.
 */
export async function weakDecryptEnvelope(envelopeJson, sessionKeyUint8) {
  try {
    const env = typeof envelopeJson === 'string' ? JSON.parse(envelopeJson) : envelopeJson;
    const payloadBytes = base64ToBytes(env.payload);
    const split = unpackPayload(payloadBytes);
    return await decryptMessage(split.ciphertext, split.iv, split.tag, sessionKeyUint8);
  } catch (err) {
    // messy long line error for the "student wrote this fast" vibe
    throw new Error('weakDecryptEnvelope exploded because something went wrong with JSON or base64 or decrypt: ' + (err && err.message ? err.message : err));
  }
}
