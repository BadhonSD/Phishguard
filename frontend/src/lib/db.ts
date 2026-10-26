const DB_NAME = "phishguard";
const DB_VERSION = 1;
const STORE_NAME = "history";
const MAX_ENTRIES = 20;

export interface HistoryEntry {
  id?: number;
  url: string;
  isPhishing: boolean;
  confidence: number;
  source: "manual" | "qr";
  timestamp: number;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof window === "undefined") {
      reject(new Error("IndexedDB is only available in the browser"));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: "id", autoIncrement: true });
        store.createIndex("timestamp", "timestamp");
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function addHistoryEntry(entry: Omit<HistoryEntry, "timestamp">): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).add({ ...entry, timestamp: Date.now() });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  await trimHistory(db);
  db.close();
}

async function trimHistory(db: IDBDatabase): Promise<void> {
  const all = await getAllEntries(db);
  if (all.length <= MAX_ENTRIES) return;
  const toDelete = all
    .sort((a, b) => a.timestamp - b.timestamp)
    .slice(0, all.length - MAX_ENTRIES);
  
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  for (const entry of toDelete) {
    if (entry.id !== undefined) {
      store.delete(entry.id);
    }
  }
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function getAllEntries(existingDb?: IDBDatabase): Promise<HistoryEntry[]> {
  return new Promise(async (resolve, reject) => {
    try {
      const db = existingDb || (await openDb());
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).getAll();
      req.onsuccess = () => resolve(req.result as HistoryEntry[]);
      req.onerror = () => reject(req.error);
    } catch (err) {
      reject(err);
    }
  });
}

export async function getHistory(): Promise<HistoryEntry[]> {
  try {
    const entries = await getAllEntries();
    return entries.sort((a, b) => b.timestamp - a.timestamp);
  } catch (err) {
    console.error("Failed to load history from IndexedDB", err);
    return [];
  }
}
