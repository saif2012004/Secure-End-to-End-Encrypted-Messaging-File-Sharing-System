import { hkdf } from '../utils/hkdf';
import { clearReplayState } from './encryptionService';
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  utf8ToBytes,
  randomBytes,
  concatBytes,
} from '../utils/base64';
import { useAuthStore } from '../store/authStore';
import { logEvent } from './loggingService';

const DB_NAME = 'key-exchange-db';
const DB_VERSION = 1;
let dbPromise;
let socketRef = null;
const sessionCache = new Map();
const handshakeCache = new Map();
const identityCache = {};
const MAX_SKEW_MS = 30_000; // ±30s freshness window for KE messages

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains('sessions')) db.createObjectStore('sessions', { keyPath: 'userId' });
      if (!db.objectStoreNames.contains('nonces_out')) db.createObjectStore('nonces_out', { keyPath: 'nonce' });
      if (!db.objectStoreNames.contains('nonces_in')) db.createObjectStore('nonces_in', { keyPath: 'nonce' });
      if (!db.objectStoreNames.contains('identity')) db.createObjectStore('identity', { keyPath: 'id' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

async function putValue(store, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
  });
}

async function getValue(store, key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

const rememberOutgoingNonce = (nonce) => putValue('nonces_out', { nonce, ts: Date.now() });
const rememberIncomingNonce = (nonce) => putValue('nonces_in', { nonce, ts: Date.now() });
const seenIncomingNonce = async (nonce) => !!(await getValue('nonces_in', nonce));

async function persistSession(userId, keyRawBytes, seq = 0, username) {
  const keyRaw = keyRawBytes instanceof ArrayBuffer ? new Uint8Array(keyRawBytes) : keyRawBytes;
  return putValue('sessions', {
    userId,
    key: arrayBufferToBase64(keyRaw),
    seq,
    username,
    updatedAt: Date.now(),
  });
}

async function loadSession(userId) {
  const record = await getValue('sessions', userId);
  if (!record) return null;
  const keyBytes = new Uint8Array(base64ToArrayBuffer(record.key));
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt'],
  );
  const session = { key, keyBytes, seq: record.seq || 0, username: record.username };
  sessionCache.set(userId, session);
  return session;
}

async function ensureIdentityKeys() {
  if (identityCache.self) return identityCache.self;
  const stored = await getValue('identity', 'self');
  if (stored?.pub && stored?.priv) {
    const publicKey = await crypto.subtle.importKey(
      'spki',
      base64ToArrayBuffer(stored.pub),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      stored.priv,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign'],
    );
    identityCache.self = { publicKey, privateKey, pubB64: stored.pub };
    logEvent('identity_loaded', { pub: stored.pub });
    return identityCache.self;
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const pub = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const priv = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const pubB64 = arrayBufferToBase64(pub);
  await putValue('identity', { id: 'self', pub: pubB64, priv });
  identityCache.self = { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, pubB64 };
  logEvent('identity_generated', { pub: pubB64 });
  return identityCache.self;
}

export async function getIdentityPublicB64() {
  const identity = await ensureIdentityKeys();
  return identity.pubB64;
}

async function signPayload(payload) {
  const identity = await ensureIdentityKeys();
  const data = utf8ToBytes(JSON.stringify(payload));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, identity.privateKey, data);
  return arrayBufferToBase64(sig);
}

async function verifyPayload(payload, signatureB64, publicKeyB64) {
  if (!signatureB64 || !publicKeyB64) return false;
  const key = await crypto.subtle.importKey('spki', base64ToArrayBuffer(publicKeyB64), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const data = utf8ToBytes(JSON.stringify(payload));
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, base64ToArrayBuffer(signatureB64), data);
}

async function deriveSessionKeys(peerPublicKeyB64, localPrivateKey, initNonce, respNonce) {
  const peerKey = await crypto.subtle.importKey(
    'raw',
    base64ToArrayBuffer(peerPublicKeyB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, localPrivateKey, 256);
  const salt = concatBytes(base64ToArrayBuffer(initNonce), base64ToArrayBuffer(respNonce));
  const info = utf8ToBytes('secure-chat-session');
  const material = await hkdf(shared, salt, info, 64);
  const encMaterial = material.slice(0, 32);
  const macMaterial = material.slice(32);

  const sessionKey = await crypto.subtle.importKey('raw', encMaterial, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  const macKey = await crypto.subtle.importKey('raw', macMaterial, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
  return { sessionKey, macKey, rawKey: encMaterial.buffer, rawKeyBytes: encMaterial };
}

const confirmData = (initNonce, respNonce) => concatBytes(base64ToArrayBuffer(initNonce), base64ToArrayBuffer(respNonce), utf8ToBytes('KEY_CONFIRM'));

async function buildMac(macKey, initNonce, respNonce) {
  const data = confirmData(initNonce, respNonce);
  const sig = await crypto.subtle.sign('HMAC', macKey, data);
  return arrayBufferToBase64(sig);
}

async function verifyMac(macKey, macB64, initNonce, respNonce) {
  const data = confirmData(initNonce, respNonce);
  return crypto.subtle.verify('HMAC', macKey, base64ToArrayBuffer(macB64), data);
}

function logComplete(username) {
  const name = username || 'peer';
  console.log(`Key exchange completed with ${name}!`);
}

function isFreshTimestamp(tsMs) {
  if (!tsMs) return false;
  const skew = Math.abs(Date.now() - Number(tsMs));
  return skew <= MAX_SKEW_MS;
}

async function cacheSession(userId, sessionKey, username) {
  const raw = sessionKey instanceof Uint8Array
    ? sessionKey
    : new Uint8Array(await crypto.subtle.exportKey('raw', sessionKey));
  await persistSession(userId, raw, 0, username);
  const cryptoKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  sessionCache.set(userId, { key: cryptoKey, keyBytes: raw, seq: 0, username });
  console.log('[keyx] session key cached for', username || userId);
  // Reset replay tracking for this peer when a new session key is established
  try {
    await clearReplayState(userId);
  } catch (e) {
    console.warn('Failed to clear replay state for', userId, e);
  }
  logEvent('session_key_cached', {
    userId,
    username,
    key_b64: arrayBufferToBase64(raw),
  });
}

async function handleKeInit(payload, meta) {
  if (!payload?.nonce || !payload?.ephPub) return;
  const ts = payload.ts || Date.now();
  if (!isFreshTimestamp(ts)) {
    console.warn('Stale KE_INIT rejected (timestamp skew too large)');
    return;
  }
  if (await seenIncomingNonce(payload.nonce)) {
    console.warn('Ignoring replayed KE_INIT');
    return;
  }
  await rememberIncomingNonce(payload.nonce);
  logEvent('ke_init_received', { from: payload.from || meta.senderId, nonce: payload.nonce, ts, mode: payload.mode || 'signed' });

  const insecure = payload.mode === 'insecure' || payload.type === 'KE_INIT_INSECURE';
  if (!insecure && meta.signature) {
    const ok = await verifyPayload(payload, meta.signature, payload.identityKey);
    if (!ok) {
      console.warn('KE_INIT signature failed');
      return;
    }
  }

  const responderKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const responderNonce = arrayBufferToBase64(randomBytes(16));
  await rememberOutgoingNonce(responderNonce);
  const identity = await ensureIdentityKeys();

  const { sessionKey, macKey, rawKeyBytes } = await deriveSessionKeys(
    payload.ephPub,
    responderKeys.privateKey,
    payload.nonce,
    responderNonce,
  );
  handshakeCache.set(payload.from || meta.senderId, {
    role: 'responder',
    initiatorNonce: payload.nonce,
    responderNonce,
    macKey,
    sessionKey,
    username: meta.senderName || payload.fromName,
    insecure,
  });

  const reply = {
    type: insecure ? 'KE_REPLY_INSECURE' : 'KE_REPLY',
    from: meta.selfId,
    to: payload.from,
    nonce: responderNonce,
    ts: Date.now(),
    ephPub: arrayBufferToBase64(await crypto.subtle.exportKey('raw', responderKeys.publicKey)),
    initiatorNonce: payload.nonce,
    identityKey: identity.pubB64,
    mode: insecure ? 'insecure' : 'signed',
  };

  const signature = insecure ? null : await signPayload(reply);
  socketRef?.emit('key-exchange:send', {
    recipientId: payload.from,
    publicKey: JSON.stringify(reply),
    signature: signature || undefined,
  });

  // Cache responder side session immediately so we can decrypt early messages
  await cacheSession(payload.from || meta.senderId, rawKeyBytes, meta.senderName || payload.fromName);
  logEvent('ke_reply_sent', {
    to: payload.from,
    nonce: responderNonce,
    initiatorNonce: payload.nonce,
    key_b64: arrayBufferToBase64(rawKeyBytes),
    mode: insecure ? 'insecure' : 'signed',
  });
}

async function handleKeReply(payload, meta) {
  const userId = payload.from || meta.senderId;
  const existing = handshakeCache.get(userId);
  if (!existing || !existing.initiatorNonce) return;

  const ts = payload.ts || Date.now();
  if (!isFreshTimestamp(ts)) {
    console.warn('Stale KE_REPLY rejected (timestamp skew too large)');
    return;
  }
  if (await seenIncomingNonce(payload.nonce)) {
    console.warn('Replay KE_REPLY ignored');
    return;
  }
  await rememberIncomingNonce(payload.nonce);

  const insecure = payload.mode === 'insecure' || payload.type === 'KE_REPLY_INSECURE' || existing.insecure;
  if (!insecure && meta.signature) {
    const ok = await verifyPayload(payload, meta.signature, payload.identityKey);
    if (!ok) return;
  }
  logEvent('ke_reply_received', { from: userId, nonce: payload.nonce, initiatorNonce: existing.initiatorNonce, mode: insecure ? 'insecure' : 'signed' });

  const derived = await deriveSessionKeys(
    payload.ephPub,
    existing.ephemeral?.privateKey || existing.ephemeralPriv,
    existing.initiatorNonce,
    payload.nonce,
  );
  const mac = await buildMac(derived.macKey, existing.initiatorNonce, payload.nonce);

  const confirm = {
    type: 'KEY_CONFIRM',
    from: meta.selfId,
    to: userId,
    mac,
    initiatorNonce: existing.initiatorNonce,
    responderNonce: payload.nonce,
    ts: Date.now(),
  };

  socketRef?.emit('key-exchange:send', {
    recipientId: userId,
    publicKey: JSON.stringify(confirm),
    signature: mac,
  });

  await cacheSession(userId, derived.sessionKey, existing.username || meta.senderName);
  logComplete(existing.username || meta.senderName);
  handshakeCache.set(userId, {
    ...existing,
    responderNonce: payload.nonce,
    macKey: derived.macKey,
    sessionKey: derived.sessionKey,
  });
  logEvent('key_confirm_sent', { to: userId, mac, initiatorNonce: existing.initiatorNonce, responderNonce: payload.nonce });
}

async function handleKeyConfirm(payload, meta) {
  const userId = payload.from || meta.senderId;
  const existing = handshakeCache.get(userId);
  if (!existing || !existing.macKey) return;

  const ts = payload.ts || Date.now();
  if (!isFreshTimestamp(ts)) {
    console.warn('Stale KEY_CONFIRM rejected (timestamp skew too large)');
    return;
  }

  const mac = payload.mac || meta.signature;
  if (!mac) return;
  const valid = await verifyMac(existing.macKey, mac, existing.initiatorNonce, existing.responderNonce);
  if (!valid) {
    console.warn('KEY_CONFIRM MAC failed');
    logEvent('key_confirm_fail', { from: userId, mac });
    return;
  }

  await cacheSession(userId, existing.sessionKey, existing.username || meta.senderName);
  logComplete(existing.username || meta.senderName);
  logEvent('key_confirm_ok', { from: userId, mac, initiatorNonce: existing.initiatorNonce, responderNonce: existing.responderNonce });
}

async function handleInbound(data) {
  let payload;
  try {
    payload = JSON.parse(data.publicKey || '{}');
  } catch (e) {
    console.error('Bad key exchange payload', e);
    return;
  }
  const authUser = useAuthStore.getState().user;
  const meta = {
    senderId: data.senderId,
    senderName: data.senderUsername,
    signature: data.signature,
    selfId: authUser?.id,
  };

  const type = payload.type;
  if (type === 'KE_INIT' || type === 'KE_INIT_INSECURE') return handleKeInit(payload, meta);
  if (type === 'KE_REPLY' || type === 'KE_REPLY_INSECURE') return handleKeReply(payload, meta);
  if (type === 'KEY_CONFIRM') return handleKeyConfirm(payload, meta);
}

export function attachSocket(socket) {
  socketRef = socket;
  if (!socketRef) return;
  socketRef.off?.('key-exchange:receive'); socketRef.on('key-exchange:receive', (data) => {
    handleInbound(data).catch((err) => console.error('Key exchange handler error', err));
  });
}

export async function startKeyExchange(userId, username, opts = {}) {
  if (!socketRef) {
    console.warn('Socket not ready for key exchange');
    return;
  }
  if (sessionCache.has(userId) || (await loadSession(userId))) return;

  console.log('[keyx] starting key exchange with', username || userId);
  const authUser = useAuthStore.getState().user;
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const nonce = arrayBufferToBase64(randomBytes(16));  await rememberOutgoingNonce(nonce);
  const identity = await ensureIdentityKeys();
  const payload = {
    type: opts.insecure ? 'KE_INIT_INSECURE' : 'KE_INIT',
    from: authUser?.id,
    fromName: authUser?.username,
    to: userId,
    nonce,
    ts: Date.now(),
    ephPub: arrayBufferToBase64(await crypto.subtle.exportKey('raw', ephemeral.publicKey)),
    identityKey: identity.pubB64,
    mode: opts.insecure ? 'insecure' : 'signed',
  };

  const signature = opts.insecure ? null : await signPayload(payload);
  handshakeCache.set(userId, {
    role: 'initiator',
    initiatorNonce: nonce,
    ephemeral,
    username,
    insecure: !!opts.insecure,
  });

  socketRef.emit('key-exchange:send', {
    recipientId: userId,
    publicKey: JSON.stringify(payload),
    signature: signature || undefined,
  });
  logEvent('ke_init_sent', { to: userId, nonce, mode: opts.insecure ? 'insecure' : 'signed' });
}

export const startInsecureKeyExchange = (userId, username) => startKeyExchange(userId, username, { insecure: true });

export async function getSessionKey(userId) {
  const cached = sessionCache.get(userId);
  if (cached?.keyBytes) return cached.keyBytes;
  const session = await loadSession(userId);
  return session?.keyBytes || null;
}

export async function nextSessionSeq(userId) {
  const cached = sessionCache.get(userId) || (await loadSession(userId));
  if (!cached) return 0;
  const nextSeq = (cached.seq || 0) + 1;
  cached.seq = nextSeq;
  sessionCache.set(userId, cached);
  await persistSession(userId, cached.keyBytes || (await crypto.subtle.exportKey('raw', cached.key)), nextSeq, cached.username);
  return nextSeq;
}

/**
 * Ensure a session key exists; if not, trigger key exchange and wait briefly.
 * Returns raw key bytes or null if timeout.
 */
export async function waitForSessionKey(userId, username, timeoutMs = 5000) {
  const existing = await getSessionKey(userId);
  if (existing) return existing;

  // kick off exchange if not already in flight
  console.log('[keyx] auto-starting key exchange for', userId, username || '');
  startKeyExchange(userId, username).catch((err) => console.error('Auto key exchange failed', err));

  const start = Date.now();
  // poll every 200ms
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const key = await getSessionKey(userId);
    if (key) return key;
    if (Date.now() - start > timeoutMs) return null;
    // small delay
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

export const keyExchangeService = {
  attachSocket,
  handleInbound,
  startKeyExchange,
  startInsecureKeyExchange,
  getSessionKey,
  nextSessionSeq,
  getIdentityPublicB64,
  waitForSessionKey,
};

export default keyExchangeService;
