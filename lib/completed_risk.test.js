import test from "node:test";
import assert from "node:assert/strict";

// Regression coverage for the reported bug: a risky download that finished
// during the analysis window had its verdict discarded ("analysis result ignored
// state=complete"), leaving a dangerous file on disk with no warning.
//
// Real-world trace being reproduced (eicar.com is tiny, so it always completes
// inside the 2s analysis window):
//   [DG] created #81 ...\eicar.com
//   [DG] pause requested #81 / paused #81
//   [DG] analysis started #81 local heuristics / analysis delay #81 2000ms
//   [DG] external state change #81 state=complete / external cleanup done #81
//   [DG] verdict #81 suspicious score=25
//   [DG] analysis result ignored #81 state=complete      <-- the bug

const sessionStorageStore = new Map();
const localStorageStore = new Map();

globalThis.chrome = {
  storage: {
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
  },
};

const mockDownloads = {
  pauseCalls: [],
  resumeCalls: [],
  cancelCalls: [],
  removeFileCalls: [],
  eraseCalls: [],
  resumeShouldFail: false,
  searchReturnState: "in_progress",
  searchHandler: null,
};

const mockNotifications = { created: [], cleared: [] };
const mockAlarms = { created: [], cleared: [] };

globalThis.chrome.downloads = {
  onCreated: { addListener: () => {} },
  onChanged: { addListener: () => {} },
  pause: async (id) => {
    mockDownloads.pauseCalls.push(id);
  },
  resume: async (id) => {
    mockDownloads.resumeCalls.push(id);
    if (mockDownloads.resumeShouldFail) {
      throw new Error("Chrome resume API error: download not in progress");
    }
  },
  cancel: async (id) => {
    mockDownloads.cancelCalls.push(id);
    throw new Error("Chrome cancel API error: download not found");
  },
  removeFile: async (id) => {
    mockDownloads.removeFileCalls.push(id);
  },
  erase: async (query) => {
    mockDownloads.eraseCalls.push(query);
  },
  search: async (query) => {
    if (mockDownloads.searchHandler) {
      return mockDownloads.searchHandler(query);
    }
    return [{ id: query.id, state: mockDownloads.searchReturnState, paused: false }];
  },
};

let notificationShouldFail = false;
globalThis.chrome.notifications = {
  create: (id, options, cb) => {
    if (notificationShouldFail) {
      mockNotifications.created.push({ id, options, failed: true });
      // Chrome sets lastError *before* invoking the callback.
      globalThis.chrome.runtime.lastError = { message: "notification failed" };
      if (cb) cb(undefined);
      return;
    }
    mockNotifications.created.push({ id, options, failed: false });
    globalThis.chrome.runtime.lastError = null;
    if (cb) cb(id);
  },
  clear: (id, cb) => {
    mockNotifications.cleared.push(id);
    if (cb) cb();
  },
  onButtonClicked: { addListener: () => {} },
  onClosed: { addListener: () => {} },
};

globalThis.chrome.alarms = {
  create: async (name, options) => {
    mockAlarms.created.push({ name, options });
  },
  clear: async (name) => {
    mockAlarms.cleared.push(name);
  },
  onAlarm: { addListener: () => {} },
};

globalThis.chrome.runtime = {
  id: "test-extension-id",
  lastError: null,
  onMessage: { addListener: () => {} },
  onInstalled: { addListener: () => {} },
  onStartup: { addListener: () => {} },
};

const {
  handleNewDownload,
  notifyCompletedRisk,
  resolveDecision,
  completedRiskNotified,
  activeResolutions,
  onDownloadsChanged,
  pendingKey,
} = await import("../background.js");

function resetMocks() {
  sessionStorageStore.clear();
  localStorageStore.clear();
  completedRiskNotified.clear();
  activeResolutions.clear();
  mockDownloads.pauseCalls = [];
  mockDownloads.resumeCalls = [];
  mockDownloads.cancelCalls = [];
  mockDownloads.removeFileCalls = [];
  mockDownloads.eraseCalls = [];
  mockDownloads.resumeShouldFail = false;
  mockDownloads.searchReturnState = "in_progress";
  mockDownloads.searchHandler = null;
  mockNotifications.created = [];
  mockNotifications.cleared = [];
  mockAlarms.created = [];
  mockAlarms.cleared = [];
  notificationShouldFail = false;
  globalThis.chrome.runtime.lastError = null;
}

// eicar.com: tiny file, .com extension => suspicious (25) on medium sensitivity.
const EICAR = {
  id: 81,
  state: "in_progress",
  url: "http://127.0.0.1:8000/eicar.com",
  filename: "C:\\Users\\test\\Downloads\\eicar.com",
};
// invoice.pdf.exe => dangerous (95).
const DANGEROUS = {
  id: 82,
  state: "in_progress",
  url: "http://127.0.0.1:8000/invoice.pdf.exe",
  filename: "invoice.pdf.exe",
};
// report.pdf over https => safe.
const SAFE = {
  id: 83,
  state: "in_progress",
  url: "https://example.com/report.pdf",
  filename: "report.pdf",
};

function completesDuringAnalysis(item) {
  mockDownloads.searchHandler = (query) => [
    { id: query.id, state: "complete", paused: false, finalUrl: item.finalUrl || item.url },
  ];
}

// --- Requirement 5a + 7: suspicious download completes during analysis

test("suspicious download that completes during analysis is now flagged (eicar.com)", async () => {
  resetMocks();
  completesDuringAnalysis(EICAR);

  await handleNewDownload(EICAR);

  assert.equal(mockNotifications.created.length, 1, "notification must be raised");
  const note = mockNotifications.created[0];
  assert.match(note.options.title, /already downloaded/i);
  assert.match(note.options.message, /finished downloading before/i);
  assert.match(note.options.message, /Delete file.*Keep file/s);
  assert.deepEqual(
    note.options.buttons.map((b) => b.title),
    ["Delete file", "Keep file"],
  );
  assert.equal(note.options.requireInteraction, true);
  assert.equal(note.options.iconUrl, "icons/icon-128.png");

  assert.equal(mockAlarms.created.length, 1, "fail-safe alarm must be set");
  assert.equal(mockAlarms.created[0].name, "dg-timeout-81");

  // The pending record must survive so resolveDecision can still act.
  const pending = sessionStorageStore.get(pendingKey(81));
  assert.ok(pending, "pending record retained for the decision");
  assert.equal(pending.verdict, "suspicious");
  assert.equal(pending.completedRisk, true);
  assert.ok(pending.filename.includes("eicar.com"));

  // We must NOT pretend the finished download can still be paused/resumed.
  assert.equal(mockDownloads.resumeCalls.length, 0, "no resume on a completed download");
  assert.equal(mockDownloads.cancelCalls.length, 0, "nothing cancelled yet - user decides");
  assert.equal(mockDownloads.removeFileCalls.length, 0, "file not deleted without consent");
});

// --- Requirement 5b + 7: dangerous download completes during analysis

test("dangerous download that completes during analysis is flagged as dangerous", async () => {
  resetMocks();
  completesDuringAnalysis(DANGEROUS);

  await handleNewDownload(DANGEROUS);

  assert.equal(mockNotifications.created.length, 1);
  assert.match(mockNotifications.created[0].options.title, /dangerous/i);

  const pending = sessionStorageStore.get(pendingKey(82));
  assert.equal(pending.verdict, "dangerous");
  assert.equal(pending.score, 95);
  assert.equal(pending.completedRisk, true);
  assert.equal(mockAlarms.created.length, 1);
});

// --- Requirement 5c + 3: notification emitted exactly once

test("repeated completion handling does not emit a duplicate notification", async () => {
  resetMocks();
  completesDuringAnalysis(EICAR);

  await handleNewDownload(EICAR);
  assert.equal(mockNotifications.created.length, 1);

  // A second state delta and a second analysis completion for the same id.
  await onDownloadsChanged({ id: 81, state: { current: "complete" } });
  await onDownloadsChanged({ id: 81, state: { current: "complete" } });
  const again = await notifyCompletedRisk(
    { id: 81, state: "complete", filename: EICAR.filename, url: EICAR.url },
    { verdict: "suspicious", reasons: [], score: 25 },
  );

  assert.equal(mockNotifications.created.length, 1, "still exactly one notification");
  assert.equal(mockAlarms.created.length, 1, "still exactly one alarm");
  assert.equal(again, "already-notified");
});

test("onDownloadsChanged leaves an awaiting-decision record and its notification alone", async () => {
  resetMocks();
  completesDuringAnalysis(EICAR);
  await handleNewDownload(EICAR);

  await onDownloadsChanged({ id: 81, state: { current: "complete" } });

  assert.ok(sessionStorageStore.has(pendingKey(81)), "pending record must survive");
  assert.equal(mockNotifications.cleared.length, 0, "live notification must not be cleared");
  assert.equal(mockAlarms.cleared.length, 0, "live alarm must not be cleared");
});

test("onDownloadsChanged still tears down an ordinary completed download", async () => {
  resetMocks();
  completesDuringAnalysis(SAFE);
  await handleNewDownload(SAFE);
  assert.equal(mockNotifications.created.length, 0, "safe download raises nothing");

  sessionStorageStore.set(pendingKey(90), { verdict: "", filename: "x.pdf" });
  await onDownloadsChanged({ id: 90, state: { current: "complete" } });
  assert.equal(sessionStorageStore.has(pendingKey(90)), false);
  assert.equal(mockNotifications.cleared.length, 1);
});

// --- Requirement 5d: no duplicate decision

test("duplicate decisions on a completed risky file resolve only once", async () => {
  resetMocks();
  completesDuringAnalysis(EICAR);
  await handleNewDownload(EICAR);

  const first = await resolveDecision(81, "cancel", "user-button");
  const second = await resolveDecision(81, "allow", "user-button");
  const third = await resolveDecision(81, "cancel", "timeout");

  assert.equal(first.ok, true);
  assert.equal(second.ok, false);
  assert.equal(second.error, "already resolved");
  assert.equal(third.error, "already resolved");

  assert.equal(mockDownloads.removeFileCalls.length, 1, "file removed exactly once");
  assert.equal(mockDownloads.eraseCalls.length, 1, "history erased exactly once");
});

test("concurrent button press and timeout resolve only once", async () => {
  resetMocks();
  completesDuringAnalysis(EICAR);
  await handleNewDownload(EICAR);

  const [a, b] = await Promise.all([
    resolveDecision(81, "cancel", "user-button"),
    resolveDecision(81, "cancel", "timeout"),
  ]);

  assert.equal([a.ok, b.ok].filter(Boolean).length, 1, "exactly one decision wins");
  assert.equal(mockDownloads.removeFileCalls.length, 1);
});

// --- Requirement 2: delete action on a completed file

test("Delete file removes the completed file from disk and records history", async () => {
  resetMocks();
  completesDuringAnalysis(EICAR);
  await handleNewDownload(EICAR);

  const res = await resolveDecision(81, "cancel", "user-button");

  assert.equal(res.ok, true);
  assert.deepEqual(mockDownloads.removeFileCalls, [81], "removeFile called on the completed id");
  assert.deepEqual(mockDownloads.eraseCalls, [{ id: 81 }]);

  const history = localStorageStore.get("decisionHistory");
  assert.equal(history.length, 1, "decision recorded in history");
  assert.equal(history[0].decision, "cancel");
  assert.equal(history[0].verdict, "suspicious");
  assert.equal(history[0].cause, "user-button");
  assert.equal(history[0].hostname, "127.0.0.1");
  assert.ok(history[0].filename.includes("eicar.com"));

  assert.equal(mockNotifications.cleared.length, 1);
  assert.deepEqual(mockAlarms.cleared, ["dg-timeout-81"]);
  assert.equal(sessionStorageStore.has(pendingKey(81)), false);
});

// --- Requirement 2: explicit keep/allow action

test("Keep file leaves the completed file on disk and records history", async () => {
  resetMocks();
  completesDuringAnalysis(EICAR);
  await handleNewDownload(EICAR);
  // A completed download cannot be resumed; resume() throws.
  mockDownloads.resumeShouldFail = true;
  mockDownloads.searchReturnState = "complete";

  const res = await resolveDecision(81, "allow", "user-button");

  assert.equal(res.ok, true, "keep must succeed even though resume is impossible");
  assert.equal(mockDownloads.removeFileCalls.length, 0, "file must NOT be deleted");
  assert.equal(mockDownloads.eraseCalls.length, 0, "download entry must NOT be erased");

  const history = localStorageStore.get("decisionHistory");
  assert.equal(history.length, 1);
  assert.equal(history[0].decision, "allow");
  assert.equal(history[0].verdict, "suspicious");
  assert.equal(sessionStorageStore.has(pendingKey(81)), false, "state cleaned up");
  assert.equal(mockNotifications.cleared.length, 1);
});

// --- Requirement 4: dangerous vs suspicious consistency, fail safe

test("notification failure: dangerous file is removed, suspicious file is kept", async () => {
  // Dangerous + no notification => fail safe by deleting.
  resetMocks();
  completesDuringAnalysis(DANGEROUS);
  notificationShouldFail = true;
  await handleNewDownload(DANGEROUS);
  assert.deepEqual(mockDownloads.removeFileCalls, [82], "dangerous file removed when unnotifyable");

  // Suspicious + no notification => keep, never delete without consent.
  resetMocks();
  completesDuringAnalysis(EICAR);
  notificationShouldFail = true;
  await handleNewDownload(EICAR);
  assert.equal(mockDownloads.removeFileCalls.length, 0, "suspicious file must not be silently deleted");

  const history = localStorageStore.get("decisionHistory");
  assert.equal(history.length, 1);
  assert.equal(history[0].decision, "allow");
  assert.equal(history[0].cause, "notification-failed");
});

test("timeout fails safe to deleting the completed risky file", async () => {
  resetMocks();
  completesDuringAnalysis(EICAR);
  await handleNewDownload(EICAR);

  const res = await resolveDecision(81, "cancel", "timeout");

  assert.equal(res.ok, true);
  assert.deepEqual(mockDownloads.removeFileCalls, [81]);
  const history = localStorageStore.get("decisionHistory");
  assert.equal(history[0].cause, "timeout");
  assert.equal(history[0].decision, "cancel");
});

// --- Requirement 1 + 5e: active paused download behaviour is unchanged

test("active paused dangerous download still uses the normal hold flow", async () => {
  resetMocks();
  mockDownloads.searchReturnState = "in_progress";

  await handleNewDownload(DANGEROUS);

  assert.equal(mockNotifications.created.length, 1);
  assert.equal(
    mockNotifications.created[0].options.title,
    "Dangerous download",
    "uses the original hold notification, not the completed-file one",
  );
  assert.deepEqual(
    mockNotifications.created[0].options.buttons.map((b) => b.title),
    ["Cancel download", "Allow anyway"],
  );
  const pending = sessionStorageStore.get(pendingKey(82));
  assert.equal(pending.verdict, "dangerous");
  assert.equal(pending.completedRisk, undefined, "held downloads are not marked completedRisk");
  assert.equal(mockDownloads.removeFileCalls.length, 0, "nothing removed while still paused");
});

test("active safe download resumes and clears its pending record", async () => {
  resetMocks();
  mockDownloads.searchReturnState = "in_progress";

  await handleNewDownload(SAFE);

  assert.equal(mockNotifications.created.length, 0);
  assert.deepEqual(mockDownloads.resumeCalls, [83], "safe download resumed");
  assert.equal(sessionStorageStore.has(pendingKey(83)), false);
});

test("cancelled download during analysis still raises nothing", async () => {
  resetMocks();
  mockDownloads.searchHandler = (query) => [
    { id: query.id, state: "cancelled", paused: false },
  ];

  await handleNewDownload(DANGEROUS);

  assert.equal(mockNotifications.created.length, 0);
  assert.equal(mockDownloads.removeFileCalls.length, 0);
  assert.equal(sessionStorageStore.has(pendingKey(82)), false);
});

test("interrupted download during analysis still raises nothing", async () => {
  resetMocks();
  mockDownloads.searchHandler = (query) => [
    { id: query.id, state: "interrupted", paused: false },
  ];

  await handleNewDownload(DANGEROUS);

  assert.equal(mockNotifications.created.length, 0);
  assert.equal(sessionStorageStore.has(pendingKey(82)), false);
});

// --- Existing held-download decision semantics must not regress

test("resume failure on a still-paused download still preserves state and retries", async () => {
  resetMocks();
  sessionStorageStore.set(pendingKey(77), { verdict: "dangerous", score: 95 });
  mockDownloads.resumeShouldFail = true;
  mockDownloads.searchReturnState = "in_progress";

  const res = await resolveDecision(77, "allow", "user-button");

  assert.equal(res.ok, false, "a genuinely paused download that cannot resume is still an error");
  assert.match(res.error, /resume/i);
  assert.ok(sessionStorageStore.has(pendingKey(77)), "pending preserved for retry");
  assert.equal(activeResolutions.has(77), false, "unlocked for retry");
});
