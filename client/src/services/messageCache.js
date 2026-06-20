// Persistent local cache of DECRYPTED message plaintext (this device only).
// Once a message has been decrypted, we remember it so history stays readable
// across reloads and session-key rotation. This is the "persistent" half of
// persistent/ratcheting message keys — the device keeps what it has decrypted,
// analogous to how Signal stores decrypted messages locally.

const DB_NAME = 'securechat_msg_cache';
const STORE = 'plaintext';
const DB_VERSION = 1;
let dbPromise;

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

export async function cachePlaintext(id, text) {
  if (!id || typeof text !== 'string') return;
  try {
    const db = await openDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put({ id: String(id), text, ts: Date.now() });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch (e) {
    // Caching is best-effort; never block messaging on it.
    console.warn('cachePlaintext failed', e);
  }
}

export async function getCachedPlaintext(id) {
  if (!id) return null;
  try {
    const db = await openDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(String(id));
      req.onsuccess = () => resolve(req.result?.text ?? null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
}
