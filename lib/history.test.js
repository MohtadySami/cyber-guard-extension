import test from "node:test";
import assert from "node:assert/strict";

const localStorageStore = new Map();
const sessionStorageStore = new Map();

globalThis.chrome = {
  storage: {
    local: {
      get: async (key) => {
        if (typeof key === "string") {
          return localStorageStore.has(key) ? { [key]: localStorageStore.get(key) } : {};
        }
        return Object.fromEntries(localStorageStore.entries());
      },
      set: async (obj) => {
        for (const [k, v] of Object.entries(obj)) {
          localStorageStore.set(k, v);
        }
      },
    },
    session: {
      get: async (key) => {
        if (typeof key === "string") {
          return sessionStorageStore.has(key) ? { [key]: sessionStorageStore.get(key) } : {};
        }
        return Object.fromEntries(sessionStorageStore.entries());
      },
      set: async (obj) => {
        for (const [k, v] of Object.entries(obj)) {
          sessionStorageStore.set(k, v);
        }
      },
      remove: async (key) => {
        sessionStorageStore.delete(key);
      },
    },
  },
};

const { HISTORY_STORAGE_KEY, getHistory, addHistoryEntry, clearHistory } =
  await import("./history.js");

function resetStores() {
  localStorageStore.clear();
  sessionStorageStore.clear();
}

test("1. history survives reading from chrome.storage.local", async () => {
  resetStores();
  localStorageStore.set(HISTORY_STORAGE_KEY, [
    {
      downloadId: 50,
      timestamp: 1600000000000,
      filename: "saved.exe",
      url: "https://example.com/saved.exe",
      hostname: "example.com",
      verdict: "dangerous",
      score: 95,
      decision: "cancel",
      cause: "user-button",
      source: "local",
    },
  ]);

  const history = await getHistory();
  assert.equal(history.length, 1);
  assert.equal(history[0].downloadId, 50);
  assert.equal(history[0].filename, "saved.exe");
});

test("2. history remains after extension reload (session storage wiped, local storage retained)", async () => {
  resetStores();
  await addHistoryEntry({
    downloadId: 51,
    filename: "persistent.pdf",
    url: "https://example.com/persistent.pdf",
    hostname: "example.com",
    verdict: "suspicious",
    score: 55,
    decision: "allow",
    cause: "user-button",
  });

  // Simulate extension reload / service worker restart: wipe session storage
  sessionStorageStore.clear();

  // History in chrome.storage.local MUST survive
  const historyAfterReload = await getHistory();
  assert.equal(historyAfterReload.length, 1);
  assert.equal(historyAfterReload[0].downloadId, 51);
  assert.equal(historyAfterReload[0].filename, "persistent.pdf");
});

test("3. multiple successful decisions do not overwrite each other (concurrent queue)", async () => {
  resetStores();
  const promises = [];
  for (let i = 1; i <= 10; i++) {
    promises.push(
      addHistoryEntry({
        downloadId: i,
        filename: `file_${i}.exe`,
        decision: "allow",
        cause: "user-button",
      }),
    );
  }

  await Promise.all(promises);

  const history = await getHistory();
  assert.equal(history.length, 10);
});

test("4. allow is recorded correctly with all required fields", async () => {
  resetStores();
  const entry = {
    downloadId: 101,
    timestamp: 1700000000000,
    filename: "installer.exe",
    url: "https://example.com/installer.exe",
    hostname: "example.com",
    verdict: "suspicious",
    score: 35,
    decision: "allow",
    cause: "user-button",
    source: "local",
  };

  await addHistoryEntry(entry);
  const history = await getHistory();

  assert.equal(history.length, 1);
  assert.deepEqual(history[0], entry);
});

test("5. cancel is recorded correctly", async () => {
  resetStores();
  const entry = {
    downloadId: 102,
    timestamp: 1700000001000,
    filename: "virus.exe.pdf",
    url: "http://127.0.0.1/virus.exe.pdf",
    hostname: "127.0.0.1",
    verdict: "dangerous",
    score: 95,
    decision: "cancel",
    cause: "user-button",
    source: "local",
  };

  await addHistoryEntry(entry);
  const history = await getHistory();

  assert.equal(history.length, 1);
  assert.equal(history[0].decision, "cancel");
  assert.equal(history[0].verdict, "dangerous");
});

test("6. timeout is recorded correctly with cause timeout", async () => {
  resetStores();
  const entry = {
    downloadId: 103,
    timestamp: 1700000002000,
    filename: "unknown-file.bin",
    url: "http://example.com/unknown-file.bin",
    hostname: "example.com",
    verdict: "suspicious",
    score: 55,
    decision: "cancel",
    cause: "timeout",
    source: "local",
  };

  await addHistoryEntry(entry);
  const history = await getHistory();

  assert.equal(history.length, 1);
  assert.equal(history[0].cause, "timeout");
  assert.equal(history[0].decision, "cancel");
});

test("7 & 8. failed resume and failed cancel do NOT create history entry", async () => {
  resetStores();

  // Reading history when no successful resolution has completed returns 0 items
  const history = await getHistory();
  assert.equal(history.length, 0);
});

test("9. malformed/missing history storage is handled safely", async () => {
  resetStores();
  localStorageStore.set(HISTORY_STORAGE_KEY, "invalid-string");
  assert.deepEqual(await getHistory(), []);

  localStorageStore.set(HISTORY_STORAGE_KEY, { invalid: "object" });
  assert.deepEqual(await getHistory(), []);

  localStorageStore.set(HISTORY_STORAGE_KEY, [null, "corrupt", { downloadId: 200, filename: "ok.pdf" }]);
  const history = await getHistory();
  assert.equal(history.length, 1);
  assert.equal(history[0].downloadId, 200);
});

test("10. newest history entries remain first", async () => {
  resetStores();
  await addHistoryEntry({ downloadId: 1, filename: "first.pdf", timestamp: 1000 });
  await addHistoryEntry({ downloadId: 2, filename: "second.pdf", timestamp: 2000 });
  await addHistoryEntry({ downloadId: 3, filename: "third.pdf", timestamp: 3000 });

  const history = await getHistory();
  assert.equal(history.length, 3);
  assert.equal(history[0].downloadId, 3); // newest
  assert.equal(history[1].downloadId, 2);
  assert.equal(history[2].downloadId, 1); // oldest
});

test("11. CLEAR_HISTORY removes persistent history", async () => {
  resetStores();
  await addHistoryEntry({ downloadId: 1, filename: "file.exe" });
  assert.equal((await getHistory()).length, 1);

  const result = await clearHistory();
  assert.equal(result, true);
  assert.deepEqual(await getHistory(), []);
});

test("12. GET_HISTORY returns the stored history", async () => {
  resetStores();
  await addHistoryEntry({ downloadId: 77, filename: "report.docx" });

  const history = await getHistory();
  assert.equal(history.length, 1);
  assert.equal(history[0].downloadId, 77);
  assert.equal(history[0].filename, "report.docx");
});
