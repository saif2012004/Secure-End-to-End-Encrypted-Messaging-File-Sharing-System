/* eslint-disable no-console */
// Client-side identity key handling.
// Everything here is intentionally verbose because I'm trying to explain the
// why as much as the how. We never ship server-side secrets from here.

import {
  encryptPrivateKeyBytes,
  decryptPrivateKeyBytes,
  saveIdentityRecord,
  loadIdentityRecord,
  formatIdentityRecord,
  parseIdentityRecord,
  bytesToBase64,
} from './storage';

const subtle = crypto.subtle;
const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' }; // NIST P-256
const X25519_PARAMS = { name: 'X25519' }; // for static Diffie-Hellman

// Compressed P-256 public key (33 bytes) because the server spec wants it.
function compressP256PublicKey(uncompressedRaw) {
  // uncompressedRaw is 0x04 || X(32) || Y(32)
  if (uncompressedRaw[0] !== 0x04 || uncompressedRaw.length !== 65) {
    throw new Error('unexpected P-256 public key format');
  }
  const x = uncompressedRaw.slice(1, 33);
  const y = uncompressedRaw.slice(33);
  const parity = y[y.length - 1] & 1;
  const prefix = parity ? 0x03 : 0x02;
  const compressed = new Uint8Array(33);
  compressed[0] = prefix;
  compressed.set(x, 1);
  return compressed;
}

// TODO: maybe add a decompress helper if we ever need to import from the 33-byte form.

export async function saveIdentityKeys(
  privateIdentityKeyEncrypted,
  publicIdentityKey,
  staticX25519Public,
  staticX25519PrivateEncrypted,
  publicIdentityKeyUncompressed,
) {
  // Everything going into IndexedDB must be encrypted already.
  const record = formatIdentityRecord({
    publicIdentityKey,
    publicIdentityKeyUncompressed,
    privateIdentityKeyEncrypted,
    staticX25519Public,
    staticX25519PrivateEncrypted,
  });
  await saveIdentityRecord(record);
  console.log('[crypto] identity keys persisted to IndexedDB (ciphertext only)');
}

export async function generateIdentityKeys(password) {
  // The password is needed here so we never end up storing raw private bytes.
  if (!password) throw new Error('password required to generate identity keys');

  console.log('[crypto] generating ECDSA P-256 signing key...');
  const signingKeyPair = await subtle.generateKey(ECDSA_PARAMS, true, ['sign', 'verify']);
  const signingPublicRaw = new Uint8Array(await subtle.exportKey('raw', signingKeyPair.publicKey)); // 65 bytes
  const signingPublicCompressed = compressP256PublicKey(signingPublicRaw); // 33 bytes (what the server wants)
  const signingPrivatePkcs8 = await subtle.exportKey('pkcs8', signingKeyPair.privateKey);

  console.log('[crypto] generating static X25519 DH key (for future sessions)...');
  const staticX25519KeyPair = await subtle.generateKey(X25519_PARAMS, true, ['deriveBits', 'deriveKey']);
  const staticPublicRaw = new Uint8Array(await subtle.exportKey('raw', staticX25519KeyPair.publicKey)); // 32 bytes
  const staticPrivatePkcs8 = await subtle.exportKey('pkcs8', staticX25519KeyPair.privateKey);

  // Encrypt private keys with PBKDF2-derived AES-GCM key. No plaintext hits disk.
  const encryptedSigningPrivate = await encryptPrivateKeyBytes(signingPrivatePkcs8, password);
  const encryptedStaticPrivate = await encryptPrivateKeyBytes(staticPrivatePkcs8, password);

  await saveIdentityKeys(
    encryptedSigningPrivate,
    signingPublicCompressed,
    staticPublicRaw,
    encryptedStaticPrivate,
    signingPublicRaw, // keep uncompressed copy for WebCrypto import later
  );

  return {
    publicIdentityKey: signingPublicCompressed,
    staticX25519Public: staticPublicRaw,
    // Returning CryptoKeys too in case the caller wants to chain usage right away.
    signingKeyPair,
    staticX25519KeyPair,
  };
}

export async function loadIdentityKeys(password) {
  if (!password) throw new Error('password required to unlock identity keys');
  console.log('[crypto] loading identity keys from IndexedDB...');

  const parsedRecord = parseIdentityRecord(await loadIdentityRecord());
  if (!parsedRecord) throw new Error('no identity keys stored yet');
  if (!parsedRecord.publicIdentityKeyUncompressed) {
    throw new Error('stored identity missing uncompressed public key; regenerate identity');
  }

  const signingPrivatePkcs8 = await decryptPrivateKeyBytes(
    parsedRecord.privateIdentityKeyEncrypted,
    password,
  );
  const staticPrivatePkcs8 = await decryptPrivateKeyBytes(
    parsedRecord.staticX25519PrivateEncrypted,
    password,
  );

  // Import the keys back into usable CryptoKey objects.
  const signingPrivateKey = await subtle.importKey(
    'pkcs8',
    signingPrivatePkcs8,
    ECDSA_PARAMS,
    false,
    ['sign'],
  );
  const signingPublicKey = await subtle.importKey(
    'raw',
    parsedRecord.publicIdentityKeyUncompressed,
    ECDSA_PARAMS,
    true,
    ['verify'],
  );

  const staticPrivateKey = await subtle.importKey(
    'pkcs8',
    staticPrivatePkcs8,
    X25519_PARAMS,
    false,
    ['deriveBits', 'deriveKey'],
  );
  const staticPublicKey = await subtle.importKey(
    'raw',
    parsedRecord.staticX25519Public,
    X25519_PARAMS,
    true,
    ['deriveBits'],
  );

  return {
    signingKeyPair: { publicKey: signingPublicKey, privateKey: signingPrivateKey },
    staticX25519KeyPair: { publicKey: staticPublicKey, privateKey: staticPrivateKey },
  };
}

export async function getMyIdentityPublicKey() {
  const parsedRecord = parseIdentityRecord(await loadIdentityRecord());
  if (!parsedRecord) throw new Error('identity not initialized yet');
  // Base64 because it is easy to shove into JSON for register API calls.
  return bytesToBase64(parsedRecord.publicIdentityKey);
}

// Quick debug helper while developing flows. Remove once UI is wired.
export async function debugDumpIdentityRecord() {
  const parsedRecord = parseIdentityRecord(await loadIdentityRecord());
  console.log('identity record (safe parts only):', {
    hasRecord: !!parsedRecord,
    // Do not log ciphertext either, just lengths to ensure things are present.
    compressedPubLen: parsedRecord?.publicIdentityKey?.length,
    uncompressedPubLen: parsedRecord?.publicIdentityKeyUncompressed?.length,
    staticPubLen: parsedRecord?.staticX25519Public?.length,
  });
}
