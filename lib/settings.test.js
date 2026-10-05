import test from "node:test";
import assert from "node:assert/strict";

const storageSessionStore = new Map();
const storageLocalStore = new Map();

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
    search: async () => [],
    pause: async () => {},
    resume: async () => {},
    cancel: async () => {},
    removeFile: async () => {},
    erase: async () => {},
  },
  runtime: {
    id: "test-extension-id",
    lastError: undefined,
    onMessage: { addListener: () => {} },
    onInstalled: { addListener: () => {} },
    onStartup: { addListener: () => {} },
  },
  alarms: {
    onAlarm: { addListener: () => {} },
    create: async () => {},
    clear: async () => {},
  },
  notifications: {
    onButtonClicked: { addListener: () => {} },
    onClosed: { addListener: () => {} },
    create: () => {},
    clear: () => {},
  },
};

globalThis.chrome.runtime.getURL = (path) => `chrome-extension://test/${path}`;
const { readFileSync } = await import("node:fs");
const { fileURLToPath } = await import("node:url");
const LOCALES_DIR = fileURLToPath(new URL("../_locales/", import.meta.url));
globalThis.fetch = async (url) => {
  const rel = String(url).replace("chrome-extension://test/", "");
  try {
    const body = readFileSync(`${LOCALES_DIR}${rel}`, "utf8");
    return { ok: true, status: 200, json: async () => JSON.parse(body) };
  } catch {
    return { ok: false, status: 404, json: async () => ({}) };
  }
};
globalThis.chrome.permissions = { contains: async () => false, request: async () => false };

const { getSettings, setSettings } = await import("../background.js");

function resetStores() {
  storageSessionStore.clear();
  storageLocalStore.clear();
}

// --- Regression 3: the removed backend feature must leave no trace in settings

test("regression: default settings no longer contain backend keys", async () => {
  resetStores();
  const settings = await getSettings();

  assert.equal("useBackend" in settings, false);
  assert.equal("backendUrl" in settings, false);
  assert.equal(settings.enabled, true);
  assert.equal(settings.sensitivity, "medium");
});

test("regression: stale backend keys are stripped when read", async () => {
  resetStores();
  storageLocalStore.set("settings", {
    enabled: true,
    sensitivity: "high",
    useBackend: true,
    backendUrl: "http://127.0.0.1:7471",
  });

  const settings = await getSettings();

  assert.equal("useBackend" in settings, false);
  assert.equal("backendUrl" in settings, false);
  // Unrelated settings are preserved.
  assert.equal(settings.sensitivity, "high");
});

test("regression: stale backend keys are removed from storage on write", async () => {
  resetStores();
  storageLocalStore.set("settings", {
    enabled: true,
    sensitivity: "medium",
    useBackend: true,
    backendUrl: "http://127.0.0.1:7471",
  });

  const saved = await setSettings({ enabled: false });

  assert.equal("useBackend" in saved, false);
  assert.equal("backendUrl" in saved, false);
  assert.equal(saved.enabled, false);

  const persisted = storageLocalStore.get("settings");
  assert.equal("useBackend" in persisted, false);
  assert.equal("backendUrl" in persisted, false);
});

test("regression: a partial update cannot reintroduce backend keys", async () => {
  resetStores();
  await setSettings({ useBackend: true, backendUrl: "http://127.0.0.1:7471" });

  const settings = await getSettings();
  assert.equal("useBackend" in settings, false);
  assert.equal("backendUrl" in settings, false);
});

test("setSettings still merges partial updates and keeps unrelated keys", async () => {
  resetStores();
  await setSettings({ trustedDomains: ["example.com"] });
  const saved = await setSettings({ sensitivity: "low" });

  assert.deepEqual(saved.trustedDomains, ["example.com"]);
  assert.equal(saved.sensitivity, "low");
  assert.equal(saved.enabled, true);
});

test("getSettings tolerates a malformed settings value", async () => {
  resetStores();
  storageLocalStore.set("settings", "not-an-object");

  const settings = await getSettings();
  assert.equal(settings.sensitivity, "medium");
  assert.equal(settings.enabled, true);
});
