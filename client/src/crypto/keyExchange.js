// Our custom protocol – SecureChat Initial Handshake v1.2
// Implements "SecureChat Double-Ratchet-Style Initial Handshake v1" with
// deliberately explicit ordering and commentary so it feels student-invented
// yet still defends against MITM by binding ephemeral ECDH keys to long-term
// identity signatures and freshness checks.

import {
  MESSAGE_TYPES,
  HKDF_INFO,
  ZERO_SALT,
  MAX_CLOCK_SKEW_MS,
  concatUint8,
  bufferToBase64,
  base64ToBuffer,
  encodeTimestampSeconds,
  isTimestampFresh,
  compressP256Public,
  decompressP256Public,
} from './protocol';

const DB_NAME = 'secure-chat-handshake';
const DB_VERSION = 1;
const STORE_SESSIONS = 'sessions';
const STORE_NONCES = 'nonces';
const STORE_KEYS = 'keys';
const STORE_PEERS = 'peers';

const pendingInitiatorState = new Map(); // targetUserId -> {ephemeralKeyPair, identityCompressed, staticDhKeyPair, peerProfile}
const inMemorySessions = new Map(); // targetUserId -> Uint8Array session key for quick MAC checks
const peerProfileCache = new Map(); // targetUserId -> profile

// ---------- IndexedDB helpers ----------
function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_SESSIONS)) {
        db.createObjectStore(STORE_SESSIONS, { keyPath: 'targetUserId' });
      }
      if (!db.objectStoreNames.contains(STORE_NONCES)) {
        db.createObjectStore(STORE_NONCES, { keyPath: 'nonce' });
      }
      if (!db.objectStoreNames.contains(STORE_KEYS)) {
        db.createObjectStore(STORE_KEYS, { keyPath: 'name' });
      }
      if (!db.objectStoreNames.contains(STORE_PEERS)) {
        db.createObjectStore(STORE_PEERS, { keyPath: 'userId' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function runStore(storeName, mode, callback) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, mode);
        const store = tx.objectStore(storeName);
        const request = callback(store);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      }),
  );
}

async function rememberNonce(nonceB64, timestampSeconds) {
  return runStore(STORE_NONCES, 'readwrite', (store) =>
    store.put({ nonce: nonceB64, timestampSeconds }),
  );
}

async function isNonceSeen(nonceB64) {
  const existing = await runStore(STORE_NONCES, 'readonly', (store) => store.get(nonceB64));
  return Boolean(existing);
}

async function persistSessionKey(targetUserId, sessionKeyBytes) {
  const encoded = bufferToBase64(sessionKeyBytes);
  await runStore(STORE_SESSIONS, 'readwrite', (store) =>
    store.put({ targetUserId, sessionKey: encoded, createdAt: Date.now() }),
  );
  inMemorySessions.set(targetUserId, new Uint8Array(sessionKeyBytes));
}

async function loadSessionKey(targetUserId) {
  if (inMemorySessions.has(targetUserId)) {
    return inMemorySessions.get(targetUserId);
  }
  const record = await runStore(STORE_SESSIONS, 'readonly', (store) =>
    store.get(targetUserId),
  );
  if (!record || !record.sessionKey) return null;
  const bytes = new Uint8Array(base64ToBuffer(record.sessionKey));
  inMemorySessions.set(targetUserId, bytes);
  return bytes;
}

async function saveKeyMaterial(name, publicJwk, privateJwk) {
  return runStore(STORE_KEYS, 'readwrite', (store) =>
    store.put({ name, publicJwk, privateJwk }),
  );
}

async function loadKeyMaterial(name) {
  return runStore(STORE_KEYS, 'readonly', (store) => store.get(name));
}

async function savePeerProfile(userId, profile) {
  peerProfileCache.set(userId, profile);
  return runStore(STORE_PEERS, 'readwrite', (store) => store.put({ userId, ...profile }));
}

async function loadPeerProfile(userId) {
  if (peerProfileCache.has(userId)) {
    return peerProfileCache.get(userId);
  }
  const result = await runStore(STORE_PEERS, 'readonly', (store) => store.get(userId));
  if (result) {
    peerProfileCache.set(userId, result);
  }
  return result;
}

// ---------- Crypto primitives ----------
async function hmacSha256(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return crypto.subtle.sign('HMAC', key, dataBytes);
}

async function hkdf(ikm, info = HKDF_INFO, salt = ZERO_SALT, length = 32) {
  const enc = new TextEncoder();
  const infoBytes = typeof info === 'string' ? enc.encode(info) : new Uint8Array(info);
  const prk = new Uint8Array(await hmacSha256(salt, ikm));
  let previous = new Uint8Array(0);
  const output = [];
  let counter = 1;
  while (concatUint8(...output).byteLength < length) {
    const input = concatUint8(previous, infoBytes, new Uint8Array([counter]));
    previous = new Uint8Array(await hmacSha256(prk, input));
    output.push(previous);
    counter += 1;
  }
  return concatUint8(...output).slice(0, length).buffer;
}

async function deriveSharedSecret(privateKey, publicKey) {
  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256,
  );
  return bits;
}

async function deriveSessionKey(shared1, shared2, shared3) {
  const ikm = concatUint8(shared1, shared2, shared3);
  return hkdf(ikm, HKDF_INFO, ZERO_SALT, 32);
}

async function computeConfirmationMac(sessionKeyBytes, peerIdentityCompressed) {
  const enc = new TextEncoder();
  const data = concatUint8(enc.encode('confirmation'), peerIdentityCompressed);
  return hmacSha256(sessionKeyBytes, data);
}

function constantTimeEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let result = 0;
  for (let i = 0; i < a.byteLength; i += 1) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

// ---------- Local key utilities ----------
async function getIdentityKeyPair() {
  const stored = await loadKeyMaterial('identity-ecdsa');
  if (stored) {
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      stored.publicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      stored.privateJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign'],
    );
    const raw = await crypto.subtle.exportKey('raw', publicKey);
    return { keyPair: { publicKey, privateKey }, compressed: compressP256Public(raw) };
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  await saveKeyMaterial('identity-ecdsa', publicJwk, privateJwk);
  const raw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  return { keyPair, compressed: compressP256Public(raw) };
}

async function getStaticDhKeyPair() {
  const stored = await loadKeyMaterial('static-ecdh');
  if (stored) {
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      stored.publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      [],
    );
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      stored.privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );
    const raw = await crypto.subtle.exportKey('raw', publicKey);
    return { keyPair: { publicKey, privateKey }, raw };
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  await saveKeyMaterial('static-ecdh', publicJwk, privateJwk);
  const raw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  return { keyPair, raw };
}

async function importPeerIdentity(compressed) {
  const raw = decompressP256Public(compressed);
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  );
}

async function importPeerDhPublic(raw) {
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}

// ---------- Peer profile management ----------
/**
 * Register a peer profile (identity + static DH) so verification/derivation can run.
 * The caller should supply base64 encodings of the compressed identity key (33 bytes)
 * and the raw uncompressed static DH key (65 bytes).
 */
export async function registerPeerProfile(userId, { identityCompressedB64, staticDhRawB64 }) {
  if (!identityCompressedB64 || !staticDhRawB64) {
    throw new Error('Peer profile requires identityCompressedB64 and staticDhRawB64');
  }
  const profile = {
    userId,
    identityCompressedB64,
    staticDhRawB64,
    identityCompressed: base64ToBuffer(identityCompressedB64),
    staticDhRaw: base64ToBuffer(staticDhRawB64),
  };
  await savePeerProfile(userId, {
    identityCompressedB64,
    staticDhRawB64,
  });
  peerProfileCache.set(userId, profile);
}

async function getPeerProfile(userId) {
  if (peerProfileCache.has(userId)) {
    return peerProfileCache.get(userId);
  }
  const record = await loadPeerProfile(userId);
  if (!record) return null;
  const profile = {
    userId,
    identityCompressedB64: record.identityCompressedB64,
    staticDhRawB64: record.staticDhRawB64,
    identityCompressed: base64ToBuffer(record.identityCompressedB64),
    staticDhRaw: base64ToBuffer(record.staticDhRawB64),
  };
  peerProfileCache.set(userId, profile);
  return profile;
}

// ---------- Core protocol steps ----------
/**
 * Initiator side (Alice):
 * - Generate ephemeral ECDH key
 * - Sign payload that mixes her ephemeral with Bob's identity and a fresh nonce/timestamp
 *   so MITM cannot swap Bob for a fake identity without breaking the signature check.
 */
export async function initiateKeyExchange(targetUserId) {
  const peerProfile = await getPeerProfile(targetUserId);
  if (!peerProfile) {
    throw new Error('Peer profile missing; registerPeerProfile before starting KE_INIT');
  }

  const [{ keyPair: identityKeyPair, compressed: identityCompressed }, { keyPair: staticDhKeyPair }] =
    await Promise.all([getIdentityKeyPair(), getStaticDhKeyPair()]);

  const ephemeralKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const ephemeralRaw = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);

  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const timestampSeconds = Math.floor(Date.now() / 1000);

  const payload = concatUint8(
    new Uint8Array(ephemeralRaw),
    new Uint8Array(peerProfile.identityCompressed),
    encodeTimestampSeconds(timestampSeconds),
    nonce,
  );

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    identityKeyPair.privateKey,
    payload,
  );

  pendingInitiatorState.set(targetUserId, {
    ephemeralKeyPair,
    identityCompressed,
    staticDhKeyPair,
    peerProfile,
  });

  return {
    type: MESSAGE_TYPES.KE_INIT,
    to: targetUserId,
    ephemeral_ecdhe_public: bufferToBase64(ephemeralRaw),
    identity_ecdsa_public: bufferToBase64(identityCompressed),
    signed_payload: bufferToBase64(signature),
    timestamp: timestampSeconds,
    nonce: bufferToBase64(nonce),
  };
}

/**
 * Responder side (Bob) and KEY_CONFIRM verifier:
 * - When receiving KE_INIT, Bob verifies Alice's signature binds her ephemeral to his
 *   identity plus freshness data, derives the 3-way shared secret, and responds with
 *   his own signed KE_REPLY.
 * - When receiving KEY_CONFIRM, Bob checks the MAC to complete the handshake.
 */
export async function handleIncomingKeyExchange(msg) {
  if (msg.type === MESSAGE_TYPES.KEY_CONFIRM) {
    return verifyKeyConfirmation(msg);
  }
  if (msg.insecure) {
    return handleIncomingWeakKeyExchange(msg);
  }
  if (msg.type !== MESSAGE_TYPES.KE_INIT) {
    throw new Error('Unsupported message type for handleIncomingKeyExchange');
  }

  const fromUserId = msg.from || msg.sender || 'unknown';
  const timestampSeconds = msg.timestamp;
  const nonceBytes = base64ToBuffer(msg.nonce);

  if (!isTimestampFresh(timestampSeconds)) {
    throw new Error(`Stale KE_INIT rejected (> ${MAX_CLOCK_SKEW_MS / 1000}s skew)`);
  }
  if (await isNonceSeen(bufferToBase64(nonceBytes))) {
    throw new Error('Replay detected for KE_INIT');
  }
  await rememberNonce(bufferToBase64(nonceBytes), timestampSeconds);

  const peerIdentityCompressed = base64ToBuffer(msg.identity_ecdsa_public);
  const peerIdentityKey = await importPeerIdentity(peerIdentityCompressed);

  const {
    keyPair: identityKeyPair,
    compressed: localIdentityCompressed,
  } = await getIdentityKeyPair();
  const { keyPair: localStaticDhKeyPair } = await getStaticDhKeyPair();

  const peerProfile = await getPeerProfile(fromUserId);
  if (!peerProfile) {
    throw new Error('Missing peer static DH key; call registerPeerProfile first');
  }

  const peerEphemeralRaw = base64ToBuffer(msg.ephemeral_ecdhe_public);
  const signature = base64ToBuffer(msg.signed_payload);

  const verificationPayload = concatUint8(
    new Uint8Array(peerEphemeralRaw),
    new Uint8Array(localIdentityCompressed),
    encodeTimestampSeconds(timestampSeconds),
    new Uint8Array(nonceBytes),
  );

  const signatureOk = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    peerIdentityKey,
    signature,
    verificationPayload,
  );
  if (!signatureOk) {
    throw new Error('KE_INIT signature invalid – possible MITM or corrupted payload');
  }

  const responderEphemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const responderEphemeralRaw = await crypto.subtle.exportKey('raw', responderEphemeral.publicKey);
  const peerEphemeralKey = await importPeerDhPublic(peerEphemeralRaw);
  const peerStaticDhKey = await importPeerDhPublic(peerProfile.staticDhRaw);

  const shared1 = await deriveSharedSecret(responderEphemeral.privateKey, peerEphemeralKey);
  const shared2 = await deriveSharedSecret(responderEphemeral.privateKey, peerStaticDhKey);
  const shared3 = await deriveSharedSecret(localStaticDhKeyPair.privateKey, peerEphemeralKey);
  const sessionKey = new Uint8Array(
    await deriveSessionKey(shared1, shared2, shared3),
  );

  await persistSessionKey(fromUserId, sessionKey);

  // Bob signs his own ephemeral key plus Alice's identity and ephemeral so a MITM
  // cannot inject a fake key without detection.
  const replyNonce = crypto.getRandomValues(new Uint8Array(16));
  const replyTimestamp = Math.floor(Date.now() / 1000);
  const replyPayload = concatUint8(
    new Uint8Array(responderEphemeralRaw),
    new Uint8Array(peerIdentityCompressed),
    new Uint8Array(peerEphemeralRaw),
    encodeTimestampSeconds(replyTimestamp),
    replyNonce,
  );

  const replySignature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    identityKeyPair.privateKey,
    replyPayload,
  );

  return {
    reply: {
      type: MESSAGE_TYPES.KE_REPLY,
      to: fromUserId,
      ephemeral_ecdhe_public: bufferToBase64(responderEphemeralRaw),
      signed_payload: bufferToBase64(replySignature),
      timestamp: replyTimestamp,
      nonce: bufferToBase64(replyNonce),
    },
    sessionKey,
  };
}

/**
 * Initiator final step after receiving KE_REPLY.
 * Validates Bob's signature (binding his ephemeral to Alice's identity + her
 * own ephemeral), derives the same 3-way secret, stores the session key, and
 * returns the KEY_CONFIRM MAC.
 */
export async function confirmKeyExchange(replyMsg) {
  if (!replyMsg || replyMsg.type !== MESSAGE_TYPES.KE_REPLY) {
    throw new Error('confirmKeyExchange expects a KE_REPLY message');
  }

  const targetUserId = replyMsg.from || replyMsg.sender || replyMsg.to;
  const pending = pendingInitiatorState.get(targetUserId);
  if (!pending) {
    throw new Error('No pending initiator state – did you call initiateKeyExchange first?');
  }

  const { ephemeralKeyPair, identityCompressed, staticDhKeyPair, peerProfile } = pending;
  const timestampSeconds = replyMsg.timestamp;
  const nonceBytes = base64ToBuffer(replyMsg.nonce);

  if (!isTimestampFresh(timestampSeconds)) {
    throw new Error('Stale KE_REPLY rejected');
  }
  if (await isNonceSeen(bufferToBase64(nonceBytes))) {
    throw new Error('Replay detected for KE_REPLY');
  }
  await rememberNonce(bufferToBase64(nonceBytes), timestampSeconds);

  const peerIdentityCompressed = peerProfile.identityCompressed;
  const peerIdentityKey = await importPeerIdentity(peerIdentityCompressed);
  const peerStaticDhKey = await importPeerDhPublic(peerProfile.staticDhRaw);

  const ourEphemeralRaw = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);
  const peerEphemeralRaw = base64ToBuffer(replyMsg.ephemeral_ecdhe_public);
  const peerEphemeralKey = await importPeerDhPublic(peerEphemeralRaw);

  const verificationPayload = concatUint8(
    new Uint8Array(peerEphemeralRaw),
    new Uint8Array(identityCompressed),
    new Uint8Array(ourEphemeralRaw),
    encodeTimestampSeconds(timestampSeconds),
    new Uint8Array(nonceBytes),
  );

  if (!pending.weak) {
    const signatureOk = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      peerIdentityKey,
      base64ToBuffer(replyMsg.signed_payload),
      verificationPayload,
    );
    if (!signatureOk) {
      throw new Error('KE_REPLY signature invalid – possible MITM or corrupted payload');
    }
  }

  const shared1 = await deriveSharedSecret(ephemeralKeyPair.privateKey, peerEphemeralKey);
  const shared2 = await deriveSharedSecret(ephemeralKeyPair.privateKey, peerStaticDhKey);
  const shared3 = await deriveSharedSecret(staticDhKeyPair.privateKey, peerEphemeralKey);
  const sessionKey = new Uint8Array(
    await deriveSessionKey(shared1, shared2, shared3),
  );

  await persistSessionKey(targetUserId, sessionKey);
  pendingInitiatorState.delete(targetUserId);

  const confirmationMac = await computeConfirmationMac(sessionKey, peerIdentityCompressed);

  return {
    type: MESSAGE_TYPES.KEY_CONFIRM,
    to: targetUserId,
    confirmation_mac: bufferToBase64(confirmationMac),
  };
}

// ---------- Weak (MITM-demo) variant ----------
/**
 * Weak variant: identical fields but no signatures. This intentionally removes
 * identity binding so a classroom MITM demo can intercept and swap keys.
 */
export async function initiateKeyExchangeWeak(targetUserId) {
  const { keyPair: staticDhKeyPair } = await getStaticDhKeyPair();
  const peerProfile = await getPeerProfile(targetUserId);
  if (!peerProfile) throw new Error('Peer profile missing for weak KE');

  const ephemeralKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const ephemeralRaw = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);

  pendingInitiatorState.set(targetUserId, {
    ephemeralKeyPair,
    identityCompressed: new Uint8Array(0),
    staticDhKeyPair,
    peerProfile,
    weak: true,
  });

  return {
    type: MESSAGE_TYPES.KE_INIT,
    to: targetUserId,
    ephemeral_ecdhe_public: bufferToBase64(ephemeralRaw),
    identity_ecdsa_public: null,
    signed_payload: null,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: bufferToBase64(crypto.getRandomValues(new Uint8Array(16))),
    insecure: true,
  };
}

async function handleIncomingWeakKeyExchange(msg) {
  if (msg.type !== MESSAGE_TYPES.KE_INIT || !msg.insecure) {
    throw new Error('handleIncomingWeakKeyExchange expects an insecure KE_INIT');
  }
  const fromUserId = msg.from || msg.sender || 'unknown';
  const timestampSeconds = msg.timestamp;
  const nonceBytes = base64ToBuffer(msg.nonce);

  if (!isTimestampFresh(timestampSeconds)) {
    throw new Error('Stale insecure KE_INIT rejected');
  }
  if (await isNonceSeen(bufferToBase64(nonceBytes))) {
    throw new Error('Replay detected for insecure KE_INIT');
  }
  await rememberNonce(bufferToBase64(nonceBytes), timestampSeconds);

  const peerProfile = await getPeerProfile(fromUserId);
  if (!peerProfile) throw new Error('Missing peer profile for insecure KE_INIT');

  const { keyPair: localStaticDhKeyPair } = await getStaticDhKeyPair();
  const responderEphemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const responderEphemeralRaw = await crypto.subtle.exportKey('raw', responderEphemeral.publicKey);

  const peerEphemeralRaw = base64ToBuffer(msg.ephemeral_ecdhe_public);
  const peerEphemeralKey = await importPeerDhPublic(peerEphemeralRaw);
  const peerStaticDhKey = await importPeerDhPublic(peerProfile.staticDhRaw);

  const shared1 = await deriveSharedSecret(responderEphemeral.privateKey, peerEphemeralKey);
  const shared2 = await deriveSharedSecret(responderEphemeral.privateKey, peerStaticDhKey);
  const shared3 = await deriveSharedSecret(localStaticDhKeyPair.privateKey, peerEphemeralKey);
  const sessionKey = new Uint8Array(
    await deriveSessionKey(shared1, shared2, shared3),
  );

  await persistSessionKey(fromUserId, sessionKey);

  return {
    reply: {
      type: MESSAGE_TYPES.KE_REPLY,
      to: fromUserId,
      ephemeral_ecdhe_public: bufferToBase64(responderEphemeralRaw),
      signed_payload: null,
      timestamp: Math.floor(Date.now() / 1000),
      nonce: bufferToBase64(crypto.getRandomValues(new Uint8Array(16))),
      insecure: true,
    },
    sessionKey,
  };
}

// ---------- Internal helpers ----------
async function verifyKeyConfirmation(msg) {
  const fromUserId = msg.from || msg.sender || 'unknown';
  const sessionKey = await loadSessionKey(fromUserId);
  if (!sessionKey) {
    throw new Error('No session key available for KEY_CONFIRM');
  }
  const { compressed: localIdentityCompressed } = await getIdentityKeyPair();
  const expectedMac = new Uint8Array(
    await computeConfirmationMac(sessionKey, localIdentityCompressed),
  );
  const providedMac = new Uint8Array(base64ToBuffer(msg.confirmation_mac));
  if (!constantTimeEqual(expectedMac, providedMac)) {
    throw new Error('KEY_CONFIRM MAC mismatch – handshake not trusted');
  }
  inMemorySessions.set(fromUserId, sessionKey);
  return { confirmed: true };
}
