import test from "node:test";
import assert from "node:assert/strict";

// ---------------------------------------------------------------------------
// Chrome runtime stub. Every test gets a fresh stub via reset() so no test can
// leak a mutated runtime into the next one.
// ---------------------------------------------------------------------------
let runtimeStub = null;

function makeRuntimeStub() {
  const stub = {
    calls: [],
    response: { ok: true },
    _lastError: null,
    throwOnSend: null,
    intercept: null,
    sendMessage(msg, callback) {
      stub.calls.push(msg);
      if (stub.throwOnSend) {
        throw stub.throwOnSend;
      }
      if (typeof stub.intercept === "function") {
        stub.intercept(msg, callback);
        return;
      }
      if (typeof callback === "function") {
        callback(stub.response);
      }
    },
  };
  Object.defineProperty(stub, "lastError", {
    get() {
      return stub._lastError;
    },
    configurable: true,
  });
  return stub;
}

function reset() {
  runtimeStub = makeRuntimeStub();
  globalThis.chrome = { runtime: runtimeStub };
}

reset();

const { sendMessage, getVerdictPresentation, toHistoryRow, buildSettingsPatch } =
  await import("./popup-core.js");

// --- Regression 1: sendMessage must call chrome.runtime.sendMessage exactly once

test("regression: sendMessage calls chrome.runtime.sendMessage exactly once", async () => {
  reset();
  const resp = await sendMessage({ type: "GET_SETTINGS" });

  assert.equal(runtimeStub.calls.length, 1, "must not send the message twice");
  assert.deepEqual(runtimeStub.calls[0], { type: "GET_SETTINGS" });
  assert.deepEqual(resp, { ok: true });
});

test("regression: a settings save is delivered to the background only once", async () => {
  reset();
  runtimeStub.response = { ok: true, settings: { enabled: false } };

  const resp = await sendMessage({
    type: "SET_SETTINGS",
    settings: { enabled: false },
  });

  assert.equal(resp.ok, true);
  assert.equal(runtimeStub.calls.length, 1);
  assert.equal(runtimeStub.calls.filter((m) => m.type === "SET_SETTINGS").length, 1);
});

test("regression: clearing history is delivered to the background only once", async () => {
  reset();
  let clearCount = 0;
  runtimeStub.intercept = (msg, callback) => {
    if (msg && msg.type === "CLEAR_HISTORY") {
      clearCount += 1;
    }
    callback({ ok: true });
  };

  const resp = await sendMessage({ type: "CLEAR_HISTORY" });

  assert.deepEqual(resp, { ok: true });
  assert.equal(runtimeStub.calls.length, 1);
  assert.equal(clearCount, 1, "CLEAR_HISTORY must not execute twice");
});

test("regression: three sequential messages produce exactly three sends", async () => {
  reset();
  await sendMessage({ type: "GET_SETTINGS" });
  await sendMessage({ type: "SET_SETTINGS", settings: { sensitivity: "high" } });
  await sendMessage({ type: "GET_HISTORY" });

  assert.equal(runtimeStub.calls.length, 3);
  assert.deepEqual(
    runtimeStub.calls.map((m) => m.type),
    ["GET_SETTINGS", "SET_SETTINGS", "GET_HISTORY"],
  );
});

test("regression: concurrent messages each send exactly once", async () => {
  reset();
  await Promise.all([
    sendMessage({ type: "GET_SETTINGS" }),
    sendMessage({ type: "GET_HISTORY" }),
    sendMessage({ type: "CLEAR_HISTORY" }),
  ]);

  assert.equal(runtimeStub.calls.length, 3);
});

// --- Preserved error handling / return behaviour

test("sendMessage reports runtime.lastError as a normalised failure", async () => {
  reset();
  runtimeStub._lastError = { message: "Extension context invalidated" };

  const resp = await sendMessage({ type: "GET_HISTORY" });

  assert.equal(resp.ok, false);
  assert.equal(resp.error, "Extension context invalidated");
  assert.equal(runtimeStub.calls.length, 1);
});

test("sendMessage rejects a non-object response as invalid response", async () => {
  reset();
  runtimeStub.response = undefined;

  const resp = await sendMessage({ type: "GET_HISTORY" });

  assert.deepEqual(resp, { ok: false, error: "invalid response" });
});

test("sendMessage returns a failure when chrome.runtime is unavailable", async () => {
  reset();
  globalThis.chrome = {};

  const resp = await sendMessage({ type: "GET_SETTINGS" });

  assert.deepEqual(resp, { ok: false, error: "runtime unavailable" });
});

test("sendMessage returns a failure when chrome itself is missing", async () => {
  reset();
  delete globalThis.chrome;

  const resp = await sendMessage({ type: "GET_SETTINGS" });

  assert.deepEqual(resp, { ok: false, error: "runtime unavailable" });
});

test("sendMessage converts a thrown error into a normalised failure", async () => {
  reset();
  runtimeStub.throwOnSend = new Error("serialisation failed");

  const resp = await sendMessage({ type: "SET_SETTINGS", settings: {} });

  assert.deepEqual(resp, { ok: false, error: "serialisation failed" });
});

test("sendMessage resolves only once even if the callback fires twice", async () => {
  reset();
  let captured = null;
  runtimeStub.intercept = (msg, callback) => {
    captured = callback;
  };

  const pending = sendMessage({ type: "GET_SETTINGS" });
  captured({ ok: true, value: 1 });
  captured({ ok: false, value: 2 });

  assert.deepEqual(await pending, { ok: true, value: 1 });
});

// --- Regression 2: history hostname display must use the normalised schema

test("regression: history row renders the hostname from the normalised schema", () => {
  reset();
  const row = toHistoryRow({
    downloadId: 1,
    timestamp: 1700000000000,
    filename: "invoice.pdf.exe",
    url: "http://127.0.0.1:7471/invoice.pdf.exe",
    hostname: "127.0.0.1",
    verdict: "dangerous",
    score: 95,
    decision: "cancel",
    cause: "user-button",
    source: "local",
  });

  assert.equal(row.filename, "invoice.pdf.exe");
  assert.ok(
    row.meta.includes("127.0.0.1"),
    `hostname missing from meta line: "${row.meta}"`,
  );
  assert.ok(row.meta.includes("score:95"));
  assert.equal(row.verdict, "dangerous");
});

test("regression: a real history entry round-trips its hostname into the popup row", async () => {
  reset();
  // Feed an entry through the real normaliser, then render it. This is the exact
  // path the popup uses, so a schema drift in either module fails here.
  const store = new Map();
  globalThis.chrome = {
    runtime: runtimeStub,
    storage: {
      local: {
        get: async (key) => (store.has(key) ? { [key]: store.get(key) } : {}),
        set: async (obj) => {
          for (const [k, v] of Object.entries(obj)) {
            store.set(k, v);
          }
        },
      },
    },
  };
  const { addHistoryEntry, getHistory } = await import("./history.js");

  await addHistoryEntry({
    downloadId: 42,
    filename: "setup.exe",
    url: "https://evil.example.com/setup.exe",
    host: "evil.example.com",
    verdict: "suspicious",
    score: 55,
    decision: "cancel",
    cause: "timeout",
  });

  const [entry] = await getHistory();
  assert.equal(entry.hostname, "evil.example.com");
  assert.equal(entry.host, undefined, "normaliser must expose only `hostname`");

  const row = toHistoryRow(entry);
  assert.ok(
    row.meta.includes("evil.example.com"),
    `hostname missing after normalise+render: "${row.meta}"`,
  );

  reset();
});

test("history row still accepts a legacy host key", () => {
  reset();
  const row = toHistoryRow({
    filename: "legacy.exe",
    host: "legacy.example.com",
    score: 25,
  });

  assert.ok(row.meta.includes("legacy.example.com"));
});

test("history row tolerates missing, null and malformed fields", () => {
  reset();
  assert.deepEqual(toHistoryRow(null), { filename: "", meta: "", verdict: "" });
  assert.deepEqual(toHistoryRow(undefined), { filename: "", meta: "", verdict: "" });
  assert.deepEqual(toHistoryRow("nonsense"), { filename: "", meta: "", verdict: "" });

  const garbage = toHistoryRow({
    filename: 123,
    hostname: 456,
    score: "95",
    timestamp: "not-a-number",
    verdict: null,
  });
  assert.deepEqual(garbage, { filename: "", meta: "", verdict: "" });
});

test("history row omits an unparseable timestamp but keeps hostname", () => {
  reset();
  const row = toHistoryRow({
    filename: "a.pdf",
    hostname: "example.com",
    timestamp: Number.NaN,
    score: 0,
  });
  assert.ok(row.meta.includes("example.com"));
  assert.ok(row.meta.includes("score:0"));
});

// --- Verdict badges

test("verdict presentation maps the three known verdicts", () => {
  reset();
  assert.equal(getVerdictPresentation("safe").className, "verdict-safe");
  assert.equal(getVerdictPresentation("suspicious").className, "verdict-suspicious");
  assert.equal(getVerdictPresentation("dangerous").className, "verdict-dangerous");
});

test("verdict presentation returns null for unknown or missing verdicts", () => {
  reset();
  assert.equal(getVerdictPresentation("unknown"), null);
  assert.equal(getVerdictPresentation(""), null);
  assert.equal(getVerdictPresentation(undefined), null);
  assert.equal(getVerdictPresentation(7), null);
});

// --- Regression 3: the popup must not write backend settings

test("regression: buildSettingsPatch never emits backend keys", () => {
  reset();
  const patch = buildSettingsPatch({ sensitivity: "high", enabled: false });

  assert.deepEqual(patch, { sensitivity: "high", enabled: false });
  assert.equal("useBackend" in patch, false);
  assert.equal("backendUrl" in patch, false);
});

test("buildSettingsPatch defaults enabled to true and drops an invalid sensitivity", () => {
  reset();
  assert.deepEqual(buildSettingsPatch({ sensitivity: "low" }), {
    sensitivity: "low",
    enabled: true,
  });
  assert.deepEqual(buildSettingsPatch({ sensitivity: "extreme", enabled: true }), {
    enabled: true,
  });
  assert.deepEqual(buildSettingsPatch(null), { enabled: true });
});
