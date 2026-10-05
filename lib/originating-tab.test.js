// Tests for originating tab resolution and page-alert invocation.

import test from "node:test";
import assert from "node:assert/strict";

// Global mock for chrome APIs before importing background.js
let queryCalls = [];
let queryReturnValues = [];

const mockTabs = {
  async query(filter) {
    queryCalls.push(filter);
    if (queryReturnValues.length > 0) {
      return queryReturnValues.shift();
    }
    return [];
  },
};

const mockStorageLocal = {
  _data: {},
  async get(keys) {
    if (keys === null) return { ...this._data };
    if (typeof keys === "string") return { [keys]: this._data[keys] };
    const res = {};
    for (const k of keys || []) res[k] = this._data[k];
    return res;
  },
  async set(items) {
    Object.assign(this._data, items);
  },
  async remove(keys) {
    const arr = Array.isArray(keys) ? keys : [keys];
    for (const k of arr) delete this._data[k];
  },
};

const mockStorageSession = {
  _data: {},
  async get(keys) {
    if (keys === null) return { ...this._data };
    const res = {};
    for (const k of (Array.isArray(keys) ? keys : [keys])) res[k] = this._data[k];
    return res;
  },
  async set(items) {
    Object.assign(this._data, items);
  },
  async remove(keys) {
    const arr = Array.isArray(keys) ? keys : [keys];
    for (const k of arr) delete this._data[k];
  },
};

let executeScriptCalls = [];
let permissionsContainsCalls = [];
let permissionGranted = false;

globalThis.chrome = {
  tabs: mockTabs,
  storage: {
    local: mockStorageLocal,
    session: mockStorageSession,
  },
  downloads: {
    onCreated: { addListener: () => {} },
    onChanged: { addListener: () => {} },
    pause: async () => {},
    resume: async () => {},
    cancel: async () => {},
    search: async () => [],
    erase: async () => {},
    removeFile: async () => {},
  },
  runtime: {
    onMessage: { addListener: () => {} },
    onInstalled: { addListener: () => {} },
    onStartup: { addListener: () => {} },
    getURL: (p) => p,
  },
  alarms: {
    create: async () => {},
    clear: async () => {},
    onAlarm: { addListener: () => {} },
  },
  notifications: {
    create: (id, opt, cb) => cb && cb(id),
    clear: (id, cb) => cb && cb(true),
    onButtonClicked: { addListener: () => {} },
    onClosed: { addListener: () => {} },
  },
  permissions: {
    contains: async (perm) => {
      permissionsContainsCalls.push(perm);
      return permissionGranted;
    },
    request: async () => permissionGranted,
  },
  scripting: {
    executeScript: async (args) => {
      executeScriptCalls.push(args);
      return [{ result: true }];
    },
  },
};

const { resolveOriginatingTabId, maybeShowPageAlert, setSettings } = await import("../background.js");

test.beforeEach(() => {
  queryCalls = [];
  queryReturnValues = [];
  executeScriptCalls = [];
  permissionsContainsCalls = [];
  permissionGranted = false;
});

// --- Tab resolution tests ---

test("resolveOriginatingTabId uses existing valid tabId directly (no tabs query)", async () => {
  const result = await resolveOriginatingTabId({ tabId: 42 });
  assert.equal(result, 42);
  assert.equal(queryCalls.length, 0, "should not call tabs.query when tabId is already known");
});

test("resolveOriginatingTabId queries by referrer URL when tabId is missing", async () => {
  queryReturnValues = [[{ id: 99, url: "https://example.com/download" }]];
  const result = await resolveOriginatingTabId({
    referrer: "https://example.com/download",
  });
  assert.equal(result, 99);
  assert.deepEqual(queryCalls[0], { url: "https://example.com/download" });
});

test("resolveOriginatingTabId returns null when referrer has no matching open tab", async () => {
  queryReturnValues = [[]]; // No tabs match the referrer
  const result = await resolveOriginatingTabId({
    referrer: "https://example.com/download",
  });
  assert.equal(result, null, "should return null if referrer tab is not found, not fall back to active tab");
});

test("resolveOriginatingTabId returns null when no referrer and no tabId (no active-tab fallback)", async () => {
  // The function must NOT fall back to the current active tab — that would inject
  // alerts into an unrelated page the user switched to after starting the download.
  queryReturnValues = []; // even if tabs.query were called, it returns nothing
  const result = await resolveOriginatingTabId({});
  assert.equal(result, null, "must return null, never guess from active tab");
  assert.equal(queryCalls.length, 0, "must not call tabs.query without referrer evidence");
});

test("resolveOriginatingTabId returns null for non-http referrer", async () => {
  const result = await resolveOriginatingTabId({ referrer: "file:///local/file" });
  assert.equal(result, null);
  assert.equal(queryCalls.length, 0);
});

test("resolveOriginatingTabId returns null when tabId is -1", async () => {
  const result = await resolveOriginatingTabId({ tabId: -1 });
  assert.equal(result, null);
});

test("resolveOriginatingTabId returns null on malformed input", async () => {
  for (const bad of [null, undefined, "string", 42]) {
    queryCalls = [];
    const result = await resolveOriginatingTabId(bad);
    assert.equal(result, null);
  }
});

// --- Page alert gating tests ---

test("maybeShowPageAlert skips when pageAlerts setting is disabled", async () => {
  await setSettings({ pageAlerts: false });
  permissionGranted = true;
  const shown = await maybeShowPageAlert({ verdict: "dangerous", tabId: 10 });
  assert.equal(shown, false);
  assert.equal(executeScriptCalls.length, 0);
});

test("maybeShowPageAlert skips when permission is not granted", async () => {
  await setSettings({ pageAlerts: true });
  permissionGranted = false;
  const shown = await maybeShowPageAlert({ verdict: "dangerous", tabId: 10 });
  assert.equal(shown, false);
  assert.equal(executeScriptCalls.length, 0);
});

test("maybeShowPageAlert skips when no valid tabId can be resolved", async () => {
  await setSettings({ pageAlerts: true });
  permissionGranted = true;
  // No tabId, no referrer → null → shouldAlertOnPage returns false
  const shown = await maybeShowPageAlert({ verdict: "dangerous" });
  assert.equal(shown, false);
  assert.equal(executeScriptCalls.length, 0);
});

// --- Injection correctness tests ---

test("maybeShowPageAlert injects dangerous verdict payload with correct fields", async () => {
  await setSettings({ pageAlerts: true });
  permissionGranted = true;

  const shown = await maybeShowPageAlert({
    verdict: "dangerous",
    tabId: 10,
    filename: "evil.exe",
    reasons: [{ code: "DOUBLE_EXTENSION", points: 40 }],
  });

  assert.equal(shown, true);
  assert.equal(executeScriptCalls.length, 1);
  const call = executeScriptCalls[0];
  assert.equal(call.target.tabId, 10);
  assert.equal(call.world, "ISOLATED");
  assert.equal(typeof call.func, "function");
  assert.equal(call.args[0].verdict, "dangerous", "verdict must be passed through to payload");
  assert.equal(call.args[0].filename, "evil.exe");
  assert.equal(call.args[0].icon, "⚠️");
});

test("maybeShowPageAlert injects safe verdict with green icon", async () => {
  await setSettings({ pageAlerts: true });
  permissionGranted = true;

  const shown = await maybeShowPageAlert({
    verdict: "safe",
    tabId: 20,
    filename: "document.pdf",
    reasons: [],
  });

  assert.equal(shown, true);
  const call = executeScriptCalls[0];
  assert.equal(call.args[0].verdict, "safe");
  assert.equal(call.args[0].icon, "✓");
});

test("maybeShowPageAlert injects suspicious verdict with warning icon", async () => {
  await setSettings({ pageAlerts: true });
  permissionGranted = true;

  const shown = await maybeShowPageAlert({
    verdict: "suspicious",
    tabId: 30,
    filename: "update.bat",
    reasons: [],
  });

  assert.equal(shown, true);
  const call = executeScriptCalls[0];
  assert.equal(call.args[0].verdict, "suspicious");
  assert.equal(call.args[0].icon, "⚠️");
});

test("maybeShowPageAlert resolves tabId via referrer when direct tabId absent", async () => {
  await setSettings({ pageAlerts: true });
  permissionGranted = true;
  queryReturnValues = [[{ id: 55 }]];

  const shown = await maybeShowPageAlert({
    verdict: "dangerous",
    filename: "bad.exe",
    referrer: "https://example.com",
    reasons: [],
  });

  assert.equal(shown, true);
  assert.equal(executeScriptCalls[0].target.tabId, 55);
  assert.equal(executeScriptCalls[0].args[0].verdict, "dangerous");
});

test("maybeShowPageAlert falls back gracefully when executeScript throws", async () => {
  await setSettings({ pageAlerts: true });
  permissionGranted = true;

  const originalExecuteScript = globalThis.chrome.scripting.executeScript;
  globalThis.chrome.scripting.executeScript = async () => {
    throw new Error("No tab with id: 10");
  };

  const shown = await maybeShowPageAlert({
    verdict: "dangerous",
    tabId: 10,
    filename: "bad.exe",
    reasons: [],
  });

  assert.equal(shown, false, "should return false (not throw) when injection fails");
  globalThis.chrome.scripting.executeScript = originalExecuteScript;
});
