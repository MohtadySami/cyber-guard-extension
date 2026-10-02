import test from "node:test";
import assert from "node:assert/strict";

// Ensure globalThis.chrome is initialized or updated in-place to avoid ESM reference mismatches
if (!globalThis.chrome) {
  globalThis.chrome = {};
}
if (!globalThis.chrome.storage) {
  globalThis.chrome.storage = {};
}

const sessionStorageStore = new Map();
const localStorageStore = new Map();

globalThis.chrome.storage.session = {
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
};

globalThis.chrome.storage.local = {
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
};

const mockDownloads = {
  pauseCalls: [],
  resumeCalls: [],
  cancelCalls: [],
  currentState: "in_progress",
  searchHandler: null,
};

const mockNotifications = {
  created: [],
};

const mockAlarms = {
  created: [],
};

globalThis.chrome.downloads = {
  onCreated: { addListener: () => {} },
  onChanged: { addListener: () => {} },
  pause: async (id) => {
    mockDownloads.pauseCalls.push(id);
  },
  resume: async (id) => {
    mockDownloads.resumeCalls.push(id);
  },
  cancel: async (id) => {
    mockDownloads.cancelCalls.push(id);
  },
  search: async (query) => {
    if (mockDownloads.searchHandler) {
      return mockDownloads.searchHandler(query);
    }
    return [{ id: query.id, state: mockDownloads.currentState, paused: true }];
  },
};

globalThis.chrome.notifications = {
  create: (id, options, cb) => {
    mockNotifications.created.push({ id, options });
    if (cb) cb(id);
  },
  clear: (_id, cb) => cb && cb(),
  onButtonClicked: { addListener: () => {} },
  onClosed: { addListener: () => {} },
};

globalThis.chrome.alarms = {
  create: async (name, options) => {
    mockAlarms.created.push({ name, options });
  },
  clear: async () => {},
  onAlarm: { addListener: () => {} },
};

globalThis.chrome.runtime = {
  id: "test-extension-id",
  lastError: null,
  onMessage: { addListener: () => {} },
  onInstalled: { addListener: () => {} },
  onStartup: { addListener: () => {} },
};

const { handleNewDownload, pendingKey } = await import("../background.js");

function resetRaceMocks() {
  sessionStorageStore.clear();
  localStorageStore.clear();
  mockDownloads.pauseCalls = [];
  mockDownloads.resumeCalls = [];
  mockDownloads.cancelCalls = [];
  mockDownloads.currentState = "in_progress";
  mockDownloads.searchHandler = null;
  mockNotifications.created = [];
  mockAlarms.created = [];
}

// NOTE: this test previously asserted "NO notification" for a *dangerous* file
// that completed during analysis. That encoded the reported bug: the verdict was
// discarded and the dangerous file was left on disk with no warning. Behaviour
// changed deliberately - a completed dangerous download is now flagged. See
// lib/completed_risk.test.js for the full coverage of the new path.
test("Test 1 — dangerous download completes during analysis: flagged, NOT paused/resumed/cancelled", async () => {
  resetRaceMocks();
  const downloadId = 401;

  const item = {
    id: downloadId,
    state: "in_progress",
    url: "http://127.0.0.1:8000/invoice.pdf.exe",
    filename: "invoice.pdf.exe",
  };

  mockDownloads.searchHandler = (query) => {
    return [{ id: query.id, state: "complete", paused: false }];
  };

  await handleNewDownload(item);

  assert.equal(mockNotifications.created.length, 1, "Completed risky file is flagged");
  assert.equal(mockAlarms.created.length, 1, "Fail-safe alarm created");
  // A completed download must not be pretended to be pausable or resumable.
  assert.equal(mockDownloads.resumeCalls.length, 0, "No resume called");
  assert.equal(mockDownloads.cancelCalls.length, 0, "No cancel called - user decides");
  assert.equal(
    sessionStorageStore.has(pendingKey(downloadId)),
    true,
    "Pending record retained so the decision can still be recorded",
  );
  assert.equal(sessionStorageStore.get(pendingKey(downloadId)).completedRisk, true);
});

test("Test 2 — download remains in progress during analysis: notification created, alarm created, held", async () => {
  resetRaceMocks();
  const downloadId = 402;

  const item = {
    id: downloadId,
    state: "in_progress",
    url: "http://127.0.0.1:8000/invoice.pdf.exe",
    filename: "invoice.pdf.exe",
  };

  mockDownloads.currentState = "in_progress";

  await handleNewDownload(item);

  assert.equal(mockNotifications.created.length, 1, "Notification created");
  assert.equal(mockAlarms.created.length, 1, "Alarm created");
  assert.equal(sessionStorageStore.has(pendingKey(downloadId)), true, "Session pending state created");
  const pendingData = sessionStorageStore.get(pendingKey(downloadId));
  assert.equal(pendingData.verdict, "dangerous");
});

test("Test 3 — state becomes cancelled during analysis: NO hold created", async () => {
  resetRaceMocks();
  const downloadId = 403;

  const item = {
    id: downloadId,
    state: "in_progress",
    url: "http://127.0.0.1:8000/invoice.pdf.exe",
    filename: "invoice.pdf.exe",
  };

  mockDownloads.searchHandler = (query) => {
    return [{ id: query.id, state: "cancelled", paused: false }];
  };

  await handleNewDownload(item);

  assert.equal(mockNotifications.created.length, 0);
  assert.equal(mockAlarms.created.length, 0);
  assert.equal(sessionStorageStore.has(pendingKey(downloadId)), false);
});

test("Test 4 — state becomes interrupted during analysis: NO hold created", async () => {
  resetRaceMocks();
  const downloadId = 404;

  const item = {
    id: downloadId,
    state: "in_progress",
    url: "http://127.0.0.1:8000/invoice.pdf.exe",
    filename: "invoice.pdf.exe",
  };

  mockDownloads.searchHandler = (query) => {
    return [{ id: query.id, state: "interrupted", paused: false }];
  };

  await handleNewDownload(item);

  assert.equal(mockNotifications.created.length, 0);
  assert.equal(mockAlarms.created.length, 0);
  assert.equal(sessionStorageStore.has(pendingKey(downloadId)), false);
});
