import { hkdf } from '../utils/hkdf';
import { arrayBufferToBase64, base64ToArrayBuffer, utf8ToBytes, randomBytes, concatBytes } from '../utils/base64';
import { useAuthStore } from '../store/authStore';

const DB_NAME = 'key-exchange-db';
const DB_VERSION = 1;
let dbPromise;
let socketRef = null;
const sessionCache = new Map();
const handshakeCache = new Map();
const identityCache = {};

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

async function persistSession(userId, keyRaw, seq = 0, username) {
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
  const key = await crypto.subtle.importKey(
    'raw',
    base64ToArrayBuffer(record.key),
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
  const session = { key, seq: record.seq || 0, username: record.username };
  sessionCache.set(userId, session);
  return session;
}

async function ensureIdentityKeys() {
  if (identityCache.self) return identityCache.self;
  const stored = await getValue('identity', 'self');
  if (stored?.pub && stored?.priv) {
    const publicKey = await crypto.subtle.importKey('spki', base64ToArrayBuffer(stored.pub), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const privateKey = await crypto.subtle.importKey('jwk', stored.priv, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    identityCache.self = { publicKey, privateKey, pubB64: stored.pub };
    return identityCache.self;
  }

  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const priv = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const pubB64 = arrayBufferToBase64(pub);
  await putValue('identity', { id: 'self', pub: pubB64, priv });
  identityCache.self = { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, pubB64 };
  return identityCache.self;
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
  return { sessionKey, macKey, rawKey: encMaterial.buffer };
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

async function cacheSession(userId, sessionKey, username) {
  const raw = await crypto.subtle.exportKey('raw', sessionKey);
  await persistSession(userId, raw, 0, username);
  sessionCache.set(userId, { key: sessionKey, seq: 0, username });
}

async function handleKeInit(payload, meta) {
  if (!payload?.nonce || !payload?.ephPub) return;
  if (await seenIncomingNonce(payload.nonce)) {
    console.warn('Ignoring replayed KE_INIT');
    return;
  }
  await rememberIncomingNonce(payload.nonce);

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

  const { sessionKey, macKey } = await deriveSessionKeys(payload.ephPub, responderKeys.privateKey, payload.nonce, responderNonce);
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
}

async function handleKeReply(payload, meta) {
  const userId = payload.from || meta.senderId;
  const existing = handshakeCache.get(userId);
  if (!existing || !existing.initiatorNonce) return;

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

  const derived = await deriveSessionKeys(payload.ephPub, existing.ephemeral?.privateKey || existing.ephemeralPriv, existing.initiatorNonce, payload.nonce);
  const mac = await buildMac(derived.macKey, existing.initiatorNonce, payload.nonce);

  const confirm = {
    type: 'KEY_CONFIRM',
    from: meta.selfId,
    to: userId,
    mac,
    initiatorNonce: existing.initiatorNonce,
    responderNonce: payload.nonce,
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
}

async function handleKeyConfirm(payload, meta) {
  const userId = payload.from || meta.senderId;
  const existing = handshakeCache.get(userId);
  if (!existing || !existing.macKey) return;

  const mac = payload.mac || meta.signature;
  if (!mac) return;
  const valid = await verifyMac(existing.macKey, mac, existing.initiatorNonce, existing.responderNonce);
  if (!valid) {
    console.warn('KEY_CONFIRM MAC failed');
    return;
  }

  await cacheSession(userId, existing.sessionKey, existing.username || meta.senderName);
  logComplete(existing.username || meta.senderName);
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
}

export const startInsecureKeyExchange = (userId, username) => startKeyExchange(userId, username, { insecure: true });

export async function getSessionKey(userId) {
  const cached = sessionCache.get(userId);
  if (cached?.key) return cached.key;
  const session = await loadSession(userId);
  return session?.key || null;
}

export const keyExchangeService = {
  attachSocket,
  handleInbound,
  startKeyExchange,
  startInsecureKeyExchange,
  getSessionKey,
};

export default keyExchangeService;
