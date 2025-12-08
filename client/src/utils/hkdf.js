import { concatBytes } from './base64';

const textEncoder = new TextEncoder();

async function hmac(keyData, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', key, message);
}

export async function hkdf(ikm, salt = new Uint8Array(32), info = new Uint8Array(0), length = 32) {
  const ikmBytes = ikm instanceof ArrayBuffer ? new Uint8Array(ikm) : new Uint8Array(ikm || []);
  const saltBytes = salt instanceof ArrayBuffer ? new Uint8Array(salt) : new Uint8Array(salt || []);
  const infoBytes = typeof info === 'string'
    ? textEncoder.encode(info)
    : info instanceof ArrayBuffer
      ? new Uint8Array(info)
      : new Uint8Array(info || []);

  // Extract
  const prk = await hmac(saltBytes, ikmBytes);

  // Expand
  let t = new Uint8Array(0);
  let okm = new Uint8Array(0);
  let counter = 0;

  while (okm.length < length) {
    counter += 1;
    const input = concatBytes(t, infoBytes, new Uint8Array([counter]));
    t = new Uint8Array(await hmac(prk, input));
    okm = concatBytes(okm, t);
  }

  return okm.slice(0, length);
}

export default hkdf;
