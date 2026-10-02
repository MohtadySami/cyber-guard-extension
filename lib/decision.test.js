import test from "node:test";
import assert from "node:assert/strict";

// Setup global mock for chrome extension APIs before importing background.js
const storageSessionStore = new Map();
const storageLocalStore = new Map();

const mockDownloads = {
  resumeCalls: [],
  cancelCalls: [],
  removeFileCalls: [],
  eraseCalls: [],
  searchCalls: [],
  resumeShouldFail: false,
  cancelShouldFail: false,
  searchReturnState: "in_progress",
};

const mockNotifications = {
  cleared: [],
};

const mockAlarms = {
  cleared: [],
};

globalThis.chrome = {
  storage: {
    session: {
      get: async (key) => {
        if (typeof key === "string") {
          return storageSessionStore.has(key) ? { [key]: storageSessionStore.get(key) } : {};
        }
        return {};
      },
      set: async (obj) => {
        for (const [k, v] of Object.entries(obj)) {
          storageSessionStore.set(k, v);
        }
      },
      remove: async (key) => {
        storageSessionStore.delete(key);
      },
    },
    local: {
      get: async (key) => {
        if (typeof key === "string") {
          return storageLocalStore.has(key) ? { [key]: storageLocalStore.get(key) } : {};
        }
        return Object.fromEntries(storageLocalStore.entries());
      },
      set: async (obj) => {
        for (const [k, v] of Object.entries(obj)) {
          storageLocalStore.set(k, v);
        }
      },
    },
  },
  downloads: {
    onCreated: { addListener: () => {} },
    onChanged: { addListener: () => {} },
    resume: async (downloadId) => {
      mockDownloads.resumeCalls.push(downloadId);
      if (mockDownloads.resumeShouldFail) {
        throw new Error("Chrome resume API error: download interrupted");
      }
    },
    cancel: async (downloadId) => {
      mockDownloads.cancelCalls.push(downloadId);
      if (mockDownloads.cancelShouldFail) {
        throw new Error("Chrome cancel API error: download not found");
      }
    },
    removeFile: async (downloadId) => {
      mockDownloads.removeFileCalls.push(downloadId);
    },
    erase: async (downloadId) => {
      mockDownloads.eraseCalls.push(downloadId);
    },
    search: async (query) => {
      mockDownloads.searchCalls.push(query);
      return [{ id: query.id, state: mockDownloads.searchReturnState, paused: true }];
    },
  },
  notifications: {
    clear: (id, cb) => {
      mockNotifications.cleared.push(id);
      if (cb) cb(true);
    },
    onButtonClicked: { addListener: () => {} },
    onClosed: { addListener: () => {} },
  },
  alarms: {
    clear: async (name) => {
      mockAlarms.cleared.push(name);
    },
    onAlarm: { addListener: () => {} },
  },
  runtime: {
    id: "test-extension-id",
    onMessage: { addListener: () => {} },
    onInstalled: { addListener: () => {} },
    onStartup: { addListener: () => {} },
  },
};

const { resolveDecision, activeResolutions, pendingKey } = await import("../background.js");

function resetMocks() {
  storageSessionStore.clear();
  storageLocalStore.clear();
  activeResolutions.clear();
  mockDownloads.resumeCalls = [];
  mockDownloads.cancelCalls = [];
  mockDownloads.removeFileCalls = [];
  mockDownloads.eraseCalls = [];
  mockDownloads.searchCalls = [];
  mockDownloads.resumeShouldFail = false;
  mockDownloads.cancelShouldFail = false;
  mockDownloads.searchReturnState = "in_progress";
  mockNotifications.cleared = [];
  mockAlarms.cleared = [];
}

test("resolveDecision - concurrent decisions execute exactly one Chrome operation", async () => {
  resetMocks();
  const downloadId = 101;
  const key = pendingKey(downloadId);
  storageSessionStore.set(key, { verdict: "dangerous", score: 95 });

  // Fire two resolveDecision calls concurrently in the same tick
  const p1 = resolveDecision(downloadId, "allow", "user-button");
  const p2 = resolveDecision(downloadId, "cancel", "timeout");

  const [res1, res2] = await Promise.all([p1, p2]);

  assert.equal(res1.ok, true);
  assert.equal(res2.ok, false);
  assert.equal(res2.error, "already resolved");

  assert.equal(mockDownloads.resumeCalls.length, 1);
  assert.equal(mockDownloads.cancelCalls.length, 0);
  assert.equal(storageSessionStore.has(key), false); // state cleaned up after success
});

test("resolveDecision - resume failure preserves pending state, notification, and alarm", async () => {
  resetMocks();
  const downloadId = 102;
  const key = pendingKey(downloadId);
  const pendingData = { verdict: "dangerous", score: 95 };
  storageSessionStore.set(key, pendingData);

  mockDownloads.resumeShouldFail = true;

  const res = await resolveDecision(downloadId, "allow", "user-button");

  assert.equal(res.ok, false);
  assert.ok(res.error.includes("Chrome resume API error"));

  // Pending session key MUST still exist
  assert.equal(storageSessionStore.has(key), true);
  assert.deepEqual(storageSessionStore.get(key), pendingData);

  // Notification and alarm MUST NOT be cleared on failure
  assert.equal(mockNotifications.cleared.length, 0);
  assert.equal(mockAlarms.cleared.length, 0);

  // activeResolutions MUST be unlocked to allow retry
  assert.equal(activeResolutions.has(downloadId), false);
});

test("resolveDecision - cancel failure preserves pending state, notification, and alarm", async () => {
  resetMocks();
  const downloadId = 103;
  const key = pendingKey(downloadId);
  const pendingData = { verdict: "dangerous", score: 95 };
  storageSessionStore.set(key, pendingData);

  mockDownloads.cancelShouldFail = true;
  mockDownloads.searchReturnState = "in_progress"; // still in progress

  const res = await resolveDecision(downloadId, "cancel", "timeout");

  assert.equal(res.ok, false);
  assert.ok(res.error.includes("Chrome cancel API error"));

  // Pending session key MUST still exist
  assert.equal(storageSessionStore.has(key), true);

  // Notification and alarm MUST NOT be cleared on failure
  assert.equal(mockNotifications.cleared.length, 0);
  assert.equal(mockAlarms.cleared.length, 0);

  // activeResolutions MUST be unlocked to allow retry
  assert.equal(activeResolutions.has(downloadId), false);
});

test("resolveDecision - double decision after successful resolution returns already resolved", async () => {
  resetMocks();
  const downloadId = 104;
  const key = pendingKey(downloadId);
  storageSessionStore.set(key, { verdict: "dangerous", score: 95 });

  const res1 = await resolveDecision(downloadId, "allow", "user-button");
  assert.equal(res1.ok, true);

  // Second decision after first has completed
  const res2 = await resolveDecision(downloadId, "cancel", "user-button");
  assert.equal(res2.ok, false);
  assert.equal(res2.error, "already resolved");

  // Verify Chrome resume was called once, cancel was never called
  assert.equal(mockDownloads.resumeCalls.length, 1);
  assert.equal(mockDownloads.cancelCalls.length, 0);
});
