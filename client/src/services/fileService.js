// Our custom envelope format v1 - designed by group SecureChat 2025
// File transfer service: chunk encryption, upload via WS, replay-safe resume, and reassembly.

import {
  FILE_CHUNK_SIZE,
  splitIntoChunks,
  encryptFileChunk,
  decryptFileChunk,
  serializeEncryptedChunk,
  deserializeEncryptedChunk,
  combineChunks,
  encryptFilename,
  decryptFilename,
} from '../crypto/fileEncryption';

const DB_NAME = 'securechat_files';
const STORE_NAME = 'file_transfers';
const DB_VERSION = 1;

const idb = globalThis.indexedDB;

function openFileDb() {
  if (!idb) {
    throw new Error('IndexedDB not available - cannot persist file metadata');
  }
  return new Promise((resolve, reject) => {
    const req = idb.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (ev) => {
      const db = ev.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'fileId' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('Failed to open file DB'));
  });
}

async function withStore(mode, action) {
  const db = await openFileDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const store = tx.objectStore(STORE_NAME);
    let done = false;
    tx.oncomplete = () => { if (!done) done = true, resolve(); };
    tx.onerror = () => { if (!done) done = true, reject(tx.error || new Error('IndexedDB tx failed')); };
    try {
      const out = action(store);
      Promise.resolve(out).then((val) => { if (!done) done = true, resolve(val); }).catch((err) => {
        if (!done) done = true, reject(err);
      });
    } catch (err) {
      if (!done) done = true, reject(err);
    }
  });
}

export async function getFileRecord(fileId) {
  return withStore('readonly', (store) => new Promise((resolve, reject) => {
    const req = store.get(fileId);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error || new Error('Failed to load file record'));
  }));
}

async function saveFileRecord(record) {
  return withStore('readwrite', (store) => new Promise((resolve, reject) => {
    const req = store.put(record);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error || new Error('Failed to save file record'));
  }));
}

export async function deleteFileRecord(fileId) {
  return withStore('readwrite', (store) => new Promise((resolve, reject) => {
    const req = store.delete(fileId);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error || new Error('Failed to delete file record'));
  }));
}

export async function hasUploadState(fileId) {
  const rec = await getFileRecord(fileId);
  return !!(rec && rec.direction === 'upload');
}

/**
 * Core upload orchestrator. Encrypts chunks and emits over WebSocket.
 */
export async function uploadEncryptedFile({ file, sessionKeyBytes, socket, recipientId, fileId, onProgress }) {
  if (!socket || !socket.connected) {
    throw new Error('Socket not connected for file upload');
  }
  const computedFileId = fileId || (crypto.randomUUID ? crypto.randomUUID() : `file_${Date.now()}`);
  const encryptedNameB64 = await encryptFilename(file.name, sessionKeyBytes);

  // Persist minimal metadata for resume.
  const existing = await getFileRecord(computedFileId);
  const alreadySent = existing && typeof existing.uploadedUntil === 'number' ? existing.uploadedUntil : -1;

  await saveFileRecord({
    fileId: computedFileId,
    encryptedName: encryptedNameB64,
    mimeType: file.type || 'application/octet-stream',
    totalChunks: Math.ceil(file.size / FILE_CHUNK_SIZE),
    uploadedUntil: alreadySent,
    direction: 'upload',
    size: file.size,
  });

  const buffer = await file.arrayBuffer(); // read whole file first
  const chunkList = splitIntoChunks(buffer);
  const totalChunks = chunkList.length;

  for (let idx = 0; idx < totalChunks; idx += 1) {
    if (idx <= alreadySent) {
      console.log(`Skipping chunk ${idx + 1}/${totalChunks} (already sent earlier)`);
      continue;
    }
    const chunkData = chunkList[idx];
    const enc = await encryptFileChunk(chunkData, sessionKeyBytes, idx, totalChunks);
    const serialized = serializeEncryptedChunk(enc);

    const packet = {
      type: 'encrypted_chunk',
      fileId: computedFileId,
      chunkIndex: idx,
      totalChunks,
      filename: encryptedNameB64, // encrypted separately, same for all chunks
      mimeType: file.type || 'application/octet-stream',
      ciphertext: serialized.ciphertext,
      iv: serialized.iv,
      tag: serialized.tag,
      fileSize: file.size,
      recipientId,
    };

    socket.emit('encrypted_chunk', packet);

    await saveFileRecord({
      fileId: computedFileId,
      encryptedName: encryptedNameB64,
      mimeType: file.type || 'application/octet-stream',
      totalChunks,
      uploadedUntil: idx,
      direction: 'upload',
      size: file.size,
    });

    const percent = Math.round(((idx + 1) / totalChunks) * 100);
    if (onProgress) onProgress(percent);
  }

  await deleteFileRecord(computedFileId);
  return { fileId: computedFileId, totalChunks };
}

/**
 * Resume upload using persisted metadata. Caller must supply the same File object.
 */
export async function resumeUpload(params) {
  const { fileId } = params;
  const rec = await getFileRecord(fileId);
  if (!rec) {
    throw new Error('No saved upload state for this fileId');
  }
  return uploadEncryptedFile(params);
}

/**
 * Handle incoming encrypted chunk from socket. Decrypt and assemble once complete.
 */
export async function handleIncomingChunk(chunkPacket, sessionKeyBytes, onComplete) {
  if (!chunkPacket || chunkPacket.type !== 'encrypted_chunk') {
    console.warn('Ignoring non-encrypted chunk payload');
    return;
  }
  const fileId = chunkPacket.fileId;
  const total = chunkPacket.totalChunks;
  const idx = chunkPacket.chunkIndex;

  // Load or create record for this file
  const existing = (await getFileRecord(fileId)) || {
    fileId,
    direction: 'download',
    encryptedName: chunkPacket.filename,
    mimeType: chunkPacket.mimeType || 'application/octet-stream',
    totalChunks: total,
    received: {},
  };

  const receivedMap = existing.received || {};
  if (receivedMap[idx]) {
    console.log(`Duplicate chunk ${idx + 1} for file ${fileId}, skipping`);
    return;
  }

  receivedMap[idx] = {
    ciphertext: chunkPacket.ciphertext,
    iv: chunkPacket.iv,
    tag: chunkPacket.tag,
  };

  await saveFileRecord({
    ...existing,
    received: receivedMap,
  });

  const receivedCount = Object.keys(receivedMap).length;
  console.log(`Stored chunk ${idx + 1}/${total} for file ${fileId}. Received ${receivedCount}/${total}`);

  if (receivedCount !== total) {
    return; // wait for more
  }

  // We have all chunks, decrypt and assemble.
  const orderedChunks = [];
  for (let i = 0; i < total; i += 1) {
    const serialized = receivedMap[i];
    if (!serialized) {
      throw new Error(`Missing chunk index ${i} during reassembly`);
    }
    const des = deserializeEncryptedChunk(serialized);
    const plainChunk = await decryptFileChunk(des.ciphertext, des.iv, des.tag, sessionKeyBytes);
    orderedChunks.push(plainChunk);
  }

  const merged = combineChunks(orderedChunks);
  const filename = await decryptFilename(existing.encryptedName, sessionKeyBytes);
  const blob = new Blob([merged], { type: existing.mimeType || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename || 'download.bin';
  anchor.click();
  URL.revokeObjectURL(url);

  await deleteFileRecord(fileId);
  if (onComplete) onComplete({ fileId, filename, size: merged.byteLength });
}
