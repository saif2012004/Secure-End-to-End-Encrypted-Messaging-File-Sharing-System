/* eslint-disable no-console */
// NOTE: This file intentionally keeps everything vanilla Web APIs.
// The idea is to learn how to wire PBKDF2 + AES-GCM + IndexedDB without
// pulling in any helper libs (our instructor forbids that).
//
// We use this module to stash encrypted private keys. The DB only ever
// sees ciphertext + salts/ivs. The derived AES key is never stored.

const DB_NAME = 'e2ee-client-crypto';
const DB_VERSION = 1;
const STORE_NAME = 'identity';
const IDENTITY_RECORD_KEY = 'identity';

// Cryptography params (the big one is the PBKDF2 iteration count).
export const PBKDF2_ITERATIONS = 600_000; // hopefully future-proof enough for now
const SALT_LENGTH = 16; // bytes
const IV_LENGTH = 12; // bytes (AES-GCM recommendation)

const textEncoder = new TextEncoder();

// Small helper so I don't forget to wrap IndexedDB in Promises.
function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB open failed'));
  });
}

export function bytesToBase64(u8) {
  // This is ok for our small blobs (key material is short).
  let binary = '';
  u8.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

async function deriveAesKey(password, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptPrivateKeyBytes(privateKeyBytes, password) {
  // TODO: maybe move iv/salt generation to a util if we repeat it.
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const aesKey = await deriveAesKey(password, salt);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    privateKeyBytes,
  );

  return {
    cipherText: new Uint8Array(ciphertext),
    iv,
    salt,
  };
}

export async function decryptPrivateKeyBytes(encryptedBundle, password) {
  const { cipherText, iv, salt } = encryptedBundle;
  const aesKey = await deriveAesKey(password, salt);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipherText);
}

export async function saveIdentityRecord(record) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error || new Error('failed to save identity record'));

    tx.objectStore(STORE_NAME).put({
      ...record,
      id: IDENTITY_RECORD_KEY,
    });
  });
}

export async function loadIdentityRecord() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).get(IDENTITY_RECORD_KEY);

    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error || new Error('failed to read identity record'));
  });
}

export async function clearIdentityRecord() {
  // Handy for debugging account resets without having to nuke the whole origin.
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error || new Error('failed to clear identity record'));
    tx.objectStore(STORE_NAME).delete(IDENTITY_RECORD_KEY);
  });
}

// Lightweight helper to avoid silent failures and to document structure.
export function formatIdentityRecord({
  publicIdentityKey,
  publicIdentityKeyUncompressed,
  privateIdentityKeyEncrypted,
  staticX25519Public,
  staticX25519PrivateEncrypted,
}) {
  return {
    // store as base64 to avoid IndexedDB structured clone edge cases with Uint8Arrays
    publicIdentityKey: bytesToBase64(publicIdentityKey),
    // keeping the uncompressed copy around so we can re-import the public key for verifies
    publicIdentityKeyUncompressed: publicIdentityKeyUncompressed
      ? bytesToBase64(publicIdentityKeyUncompressed)
      : undefined,
    privateIdentityKeyEncrypted: {
      cipherText: bytesToBase64(privateIdentityKeyEncrypted.cipherText),
      iv: bytesToBase64(privateIdentityKeyEncrypted.iv),
      salt: bytesToBase64(privateIdentityKeyEncrypted.salt),
    },
    staticX25519Public: bytesToBase64(staticX25519Public),
    staticX25519PrivateEncrypted: {
      cipherText: bytesToBase64(staticX25519PrivateEncrypted.cipherText),
      iv: bytesToBase64(staticX25519PrivateEncrypted.iv),
      salt: bytesToBase64(staticX25519PrivateEncrypted.salt),
    },
    createdAt: Date.now(),
  };
}

export function parseIdentityRecord(rawRecord) {
  if (!rawRecord) return null;
  try {
    return {
      publicIdentityKey: base64ToBytes(rawRecord.publicIdentityKey),
      publicIdentityKeyUncompressed: rawRecord.publicIdentityKeyUncompressed
        ? base64ToBytes(rawRecord.publicIdentityKeyUncompressed)
        : null,
      privateIdentityKeyEncrypted: {
        cipherText: base64ToBytes(rawRecord.privateIdentityKeyEncrypted.cipherText),
        iv: base64ToBytes(rawRecord.privateIdentityKeyEncrypted.iv),
        salt: base64ToBytes(rawRecord.privateIdentityKeyEncrypted.salt),
      },
      staticX25519Public: base64ToBytes(rawRecord.staticX25519Public),
      staticX25519PrivateEncrypted: {
        cipherText: base64ToBytes(rawRecord.staticX25519PrivateEncrypted.cipherText),
        iv: base64ToBytes(rawRecord.staticX25519PrivateEncrypted.iv),
        salt: base64ToBytes(rawRecord.staticX25519PrivateEncrypted.salt),
      },
      createdAt: rawRecord.createdAt,
    };
  } catch (error) {
    console.error('Failed to parse identity record', error);
    return null;
  }
}
