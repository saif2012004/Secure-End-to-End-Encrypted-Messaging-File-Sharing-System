// Lightweight client-side audit logger.
// Stores events in IndexedDB so we can export them later for the report.
// WARNING: This includes session key material in base64 because the user
// explicitly requested to log exchanged keys for demo purposes. Do not use
// this in production.

const DB_NAME = 'securechat_logs';
const STORE_NAME = 'logs';
const DB_VERSION = 1;

function openLogDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (ev) => {
      const db = ev.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('log DB open failed'));
  });
}

async function addLogEntry(entry) {
  const db = await openLogDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error || new Error('log write failed'));
    tx.objectStore(STORE_NAME).add(entry);
  });
}

export async function logEvent(type, data = {}) {
  try {
    await addLogEntry({
      type,
      data,
      at: Date.now(),
    });
  } catch (err) {
    // Logging should never break main flows.
    console.warn('[log] failed to persist', type, err);
  }
}

export async function getLogs(limit = 200) {
  const db = await openLogDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.openCursor(null, 'prev'); // newest first
    const out = [];
    req.onsuccess = (e) => {
      const cursor = e.target.result;
      if (cursor && out.length < limit) {
        out.push(cursor.value);
        cursor.continue();
      }
    };
    tx.oncomplete = () => resolve(out.reverse());
    tx.onerror = () => reject(tx.error || new Error('log read failed'));
  });
}

export async function exportLogs() {
  const logs = await getLogs(1000);
  const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `securechat-logs-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export default { logEvent, getLogs, exportLogs };
