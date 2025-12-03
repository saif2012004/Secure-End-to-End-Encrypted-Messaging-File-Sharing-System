const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function arrayBufferToBase64(buffer) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer || buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64 || '');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export const utf8ToBytes = (text) => encoder.encode(text || '');
export const bytesToUtf8 = (bytes) => decoder.decode(bytes);

export function randomBytes(len = 32) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
}

export function concatBytes(...chunks) {
  const total = chunks.reduce((sum, c) => sum + (c?.length || 0), 0);
  const out = new Uint8Array(total);
  let offset = 0;
  chunks.forEach((c) => {
    const arr = c instanceof ArrayBuffer ? new Uint8Array(c) : new Uint8Array(c || []);
    out.set(arr, offset);
    offset += arr.length;
  });
  return out;
}

export default {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  utf8ToBytes,
  bytesToUtf8,
  randomBytes,
  concatBytes,
};
