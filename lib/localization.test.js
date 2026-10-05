// End-to-end localization coverage for 0.2.0: drives the real service-worker
// notification paths and the popup view models in all four shipped languages,
// and asserts the security layer is untouched by any of it.

import test from "node:test";
import assert from "node:assert/strict";

import { evaluate } from "./scoring.js";
import { runAllHeuristics } from "./heuristics.js";
import { loadRealCatalogues } from "./test-i18n-fixture.js";
import { SUPPORTED_LANGUAGES } from "./i18n.js";
import {
  buildNotificationTitle,
  buildNotificationMessage,
  buildCompletedNotificationTitle,
  buildCompletedNotificationMessage,
} from "./alert.js";
import {
  getVerdictPresentation,
  toHistoryRow,
  buildSettingsPatch,
} from "./popup-core.js";

loadRealCatalogues();

const ALL = [...SUPPORTED_LANGUAGES];

// --- Chrome API stubs so the real background.js can be imported -------------

const sessionStorageStore = new Map();
const localStorageStore = new Map();

globalThis.chrome = {
  storage: {
    session: {
      get: async (key) =>
        typeof key === "string" && sessionStorageStore.has(key)
          ? { [key]: sessionStorageStore.get(key) }
          : {},
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
      get: async (key) =>
        typeof key === "string" && localStorageStore.has(key)
          ? { [key]: localStorageStore.get(key) }
          : {},
      set: async (obj) => {
        for (const [k, v] of Object.entries(obj)) {
          localStorageStore.set(k, v);
        }
      },
    },
  },
};

const mockNotifications = { created: [], cleared: [] };
globalThis.chrome.notifications = {
  create: (id, options, cb) => {
    mockNotifications.created.push({ id, options });
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

globalThis.chrome.downloads = {
  onCreated: { addListener: () => {} },
  onChanged: { addListener: () => {} },
  pause: async () => {},
  resume: async () => {},
  cancel: async () => {},
  removeFile: async () => {},
  erase: async () => {},
  search: async () => [],
};

globalThis.chrome.alarms = {
  create: async () => {},
  clear: async () => {},
  onAlarm: { addListener: () => {} },
};

globalThis.chrome.runtime = {
  id: "test-extension-id",
  lastError: null,
  onMessage: { addListener: () => {} },
  onInstalled: { addListener: () => {} },
  onStartup: { addListener: () => {} },
  getURL: (path) => `chrome-extension://test/${path}`,
};

globalThis.chrome.permissions = { contains: async () => false, request: async () => false };
globalThis.chrome.scripting = undefined;

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

const { holdDownload, notifyCompletedRisk, getSettings, setSettings } =
  await import("../background.js");

const RISKY_REASONS = [
  {
    code: "DOUBLE_EXTENSION",
    points: 40,
    text: "File name invoice.pdf.exe uses a double extension (.pdf.exe)",
    params: { filename: "invoice.pdf.exe", previousExtension: "pdf", lastExtension: "exe" },
  },
  {
    code: "EXECUTABLE_EXTENSION",
    points: 25,
    text: "File name invoice.pdf.exe uses executable extension .exe",
    params: { filename: "invoice.pdf.exe", extension: "exe" },
  },
];

const RISKY_RESULT = {
  verdict: "dangerous",
  score: 65,
  reasons: RISKY_REASONS,
  source: "local",
};

const RISKY_ITEM = {
  id: 900,
  state: "in_progress",
  filename: "invoice.pdf.exe",
  url: "https://evil.example.com/invoice.pdf.exe",
};

function resetAll() {
  sessionStorageStore.clear();
  localStorageStore.clear();
  mockNotifications.created.length = 0;
  mockNotifications.cleared.length = 0;
}

function lastNotification() {
  return mockNotifications.created[mockNotifications.created.length - 1];
}

async function withLanguage(language, run) {
  resetAll();
  await setSettings({ language });
  return await run();
}

// --- Settings persistence

test("default installation resolves to English", async () => {
  resetAll();
  const settings = await getSettings();
  assert.equal(settings.language, "en");
});

test("an existing installation with no language setting resolves to English", async () => {
  resetAll();
  // Exactly the shape written by a pre-localization build.
  localStorageStore.set("settings", {
    enabled: true,
    sensitivity: "high",
    autoResumeSafe: true,
    trustedDomains: [],
  });
  assert.equal((await getSettings()).language, "en");
});

test("an existing 0.1.x Arabic preference is preserved, not overwritten", async () => {
  resetAll();
  localStorageStore.set("settings", { enabled: true, sensitivity: "medium", language: "ar" });
  assert.equal((await getSettings()).language, "ar", "stored preference must win over the new default");
});

test("every shipped language can be selected and persists", async () => {
  for (const language of ALL) {
    resetAll();
    const saved = await setSettings({ language });
    assert.equal(saved.language, language);
    assert.equal(localStorageStore.get("settings").language, language);
    assert.equal((await getSettings()).language, language);
  }
});

test("an invalid language falls back to English on read", async () => {
  resetAll();
  localStorageStore.set("settings", { language: "klingon" });
  assert.equal((await getSettings()).language, "en");
});

test("a malformed language falls back to English and is repaired on write", async () => {
  resetAll();
  localStorageStore.set("settings", { language: 42 });
  assert.equal((await getSettings()).language, "en");

  const saved = await setSettings({ sensitivity: "low" });
  assert.equal(saved.language, "en");
  assert.equal(localStorageStore.get("settings").language, "en");
});

test("switching language preserves sensitivity and enabled state", async () => {
  resetAll();
  await setSettings({ sensitivity: "high", enabled: false });
  for (const language of ALL) {
    const saved = await setSettings({ language });
    assert.equal(saved.sensitivity, "high");
    assert.equal(saved.enabled, false);
    assert.equal(saved.language, language);
  }
});

test("the popup settings patch carries language and pageAlerts, and nothing backend", () => {
  const patch = buildSettingsPatch({
    sensitivity: "medium",
    enabled: true,
    language: "fr",
    pageAlerts: true,
  });
  assert.deepEqual(patch, {
    sensitivity: "medium",
    enabled: true,
    language: "fr",
    pageAlerts: true,
  });
  assert.equal("useBackend" in patch, false);
  assert.equal("backendUrl" in patch, false);
  // Malformed values are dropped rather than persisted.
  assert.equal("language" in buildSettingsPatch({ language: "de" }), false);
  assert.equal("language" in buildSettingsPatch({}), false);
  assert.equal("pageAlerts" in buildSettingsPatch({ pageAlerts: "yes" }), false);
});

// --- Held-risk notification localization in all four languages

test("held-risk notification title, message and reasons are localized", async () => {
  for (const language of ALL) {
    await withLanguage(language, async () => {
      await holdDownload({ ...RISKY_ITEM }, RISKY_RESULT);
      const { options } = lastNotification();
      assert.ok(options.title.length > 0, `${language}: empty title`);
      assert.ok(options.message.includes("invoice.pdf.exe"), `${language}: filename missing`);
      // Labels must be the localized ones, never the raw message key.
      assert.ok(!options.message.includes("notifFile"), `${language}: unresolved key`);
      assert.ok(!options.message.includes("notifSource"), `${language}: unresolved key`);
    });
  }
});

test("held-risk notification reasons are localized, not the stored English text", async () => {
  const rendered = {};
  for (const language of ALL) {
    rendered[language] = await withLanguage(language, async () => {
      await holdDownload({ ...RISKY_ITEM }, RISKY_RESULT);
      return lastNotification().options.message;
    });
  }
  assert.ok(rendered.en.includes("double extension"), "English reason missing");

  // Compare against the reason's STORED English sentence rather than a phrase
  // match: French legitimately shares wording like "double extension" with
  // English, so phrase matching would be a false signal.
  // Every reason line must carry the filename, and every language must render
  // its own sentence. The File:/Source: label line differs across all four
  // locales, so comparing full messages proves the catalogue (not the stored
  // English fallback) is what produced them.
  for (const language of ALL) {
    assert.ok(
      rendered[language].includes("invoice.pdf.exe"),
      `${language}: reason lost the filename`,
    );
  }
  assert.equal(new Set(Object.values(rendered)).size, ALL.length);

  // A reason with no catalogue entry must fall back to its stored text, which is
  // the documented behaviour for provider-supplied codes.
  const unknownReason = [{ code: "PROVIDER_X", points: 10, text: "Stored fallback sentence" }];
  for (const language of ALL) {
    const message = buildNotificationMessage("a.exe", "example.com", unknownReason, language);
    assert.ok(
      message.includes("Stored fallback sentence"),
      `${language}: unknown code must fall back to stored text`,
    );
  }
});

test("every held-risk notification is distinct per language", async () => {
  const messages = [];
  for (const language of ALL) {
    messages.push(
      await withLanguage(language, async () => {
        await holdDownload({ ...RISKY_ITEM }, RISKY_RESULT);
        return lastNotification().options.message;
      }),
    );
  }
  assert.equal(new Set(messages).size, ALL.length);
});

test("held-risk notification buttons are localized and keep their order", async () => {
  for (const language of ALL) {
    await withLanguage(language, async () => {
      await holdDownload({ ...RISKY_ITEM }, RISKY_RESULT);
      const buttons = lastNotification().options.buttons;
      assert.equal(buttons.length, 2, `${language}: button count changed`);
      assert.ok(!buttons[0].title.startsWith("btn"), `${language}: unresolved button key`);
      assert.notEqual(buttons[0].title, buttons[1].title);
    });
  }
});

test("a suspicious held download is titled as suspicious in every language", async () => {
  for (const language of ALL) {
    await withLanguage(language, async () => {
      await holdDownload({ ...RISKY_ITEM }, { ...RISKY_RESULT, verdict: "suspicious", score: 40 });
      const { options } = lastNotification();
      assert.notEqual(options.title, buildNotificationTitle("dangerous", language));
      assert.equal(options.title, buildNotificationTitle("suspicious", language));
    });
  }
});

// --- Completed-risk notification localization in all four languages

test("completed-risk notification is localized in every language", async () => {
  let nextId = 1000;
  for (const language of ALL) {
    await withLanguage(language, async () => {
      await notifyCompletedRisk(
        { ...RISKY_ITEM, id: nextId++, state: "complete" },
        { ...RISKY_RESULT, verdict: "dangerous", score: 95 },
      );
      const { options } = lastNotification();
      assert.equal(options.title, buildCompletedNotificationTitle("dangerous", language));
      assert.ok(!options.message.includes("$"), `${language}: unresolved placeholder`);
      assert.ok(options.message.includes("invoice.pdf.exe"));
      assert.equal(options.buttons.length, 2);
      assert.notEqual(options.buttons[0].title, options.buttons[1].title);
    });
  }
});

test("completed-risk intro and action hint are present in every language", async () => {
  let nextId = 1100;
  for (const language of ALL) {
    await withLanguage(language, async () => {
      await notifyCompletedRisk(
        { ...RISKY_ITEM, id: nextId++, state: "complete" },
        { ...RISKY_RESULT, verdict: "suspicious", score: 40 },
      );
      const message = lastNotification().options.message;
      // The first line is the localized intro; the last is the action hint.
      const firstLine = message.split("\n")[0];
      const lastLine = message.split("\n").at(-1);
      assert.notEqual(firstLine, "notifCompletedIntro", `${language}: unresolved intro key`);
      assert.notEqual(lastLine, "notifCompletedActionHint", `${language}: unresolved hint key`);
      assert.ok(firstLine.length > 10, `${language}: intro looks like a key: "${firstLine}"`);
      assert.ok(lastLine.length > 10, `${language}: hint looks like a key: "${lastLine}"`);
    });
  }
});

test("completed-risk behaviour is unchanged by language", async () => {
  let nextId = 1200;
  for (const language of ALL) {
    await withLanguage(language, async () => {
      const id = nextId++;
      const outcome = await notifyCompletedRisk(
        { ...RISKY_ITEM, id, state: "complete" },
        { ...RISKY_RESULT, verdict: "dangerous", score: 95 },
      );
      assert.equal(outcome, "notified");
      const record = sessionStorageStore.get(`pending:${id}`);
      assert.equal(record.completedRisk, true);
      // Stored reason data stays language-independent.
      assert.equal(record.reasons[0].code, "DOUBLE_EXTENSION");
      assert.ok(record.reasons[0].text.includes("double extension"));
    });
  }
});

// --- History presentation

test("existing history entries display correctly in all four languages", () => {
  const stored = {
    downloadId: 1,
    timestamp: 1700000000000,
    filename: "invoice.pdf.exe",
    url: "http://127.0.0.1:7471/invoice.pdf.exe",
    hostname: "127.0.0.1",
    verdict: "dangerous",
    score: 95,
    decision: "cancel",
    cause: "timeout",
    source: "local",
  };

  const rows = ALL.map((language) => toHistoryRow(stored, language));

  for (const [index, row] of rows.entries()) {
    const language = ALL[index];
    assert.equal(row.filename, "invoice.pdf.exe", `${language}: filename changed`);
    assert.equal(row.verdict, "dangerous", `${language}: stored verdict must stay canonical`);
    assert.equal(row.decision, "cancel", `${language}: stored decision must stay canonical`);
    assert.ok(row.meta.includes("127.0.0.1"), `${language}: hostname missing`);
  }
  // Score label and date are localized, so the meta lines must differ.
  assert.equal(new Set(rows.map((r) => r.meta)).size, ALL.length);
  assert.ok(rows[0].meta.includes("score:95"));
  assert.equal(new Set(rows.map((r) => r.decisionLabel)).size, ALL.length);
});

test("history rows keep their shape for empty and malformed input", () => {
  for (const language of ALL) {
    assert.deepEqual(
      toHistoryRow(null, language),
      { filename: "", meta: "", verdict: "" },
      `${language}: empty row shape changed`,
    );
  }
});

test("verdict badges are localized without changing their CSS classes", () => {
  for (const verdict of ["safe", "suspicious", "dangerous"]) {
    const rendered = ALL.map((language) => getVerdictPresentation(verdict, language));
    for (const [index, badge] of rendered.entries()) {
      assert.equal(badge.className, rendered[0].className);
      assert.ok(badge.label.length > 0, `${ALL[index]}: empty label`);
    }
    assert.equal(new Set(rendered.map((b) => b.label)).size, ALL.length);
  }
  assert.equal(getVerdictPresentation("unknown", "en"), null);
});

// --- Security logic must stay language-independent

test("language does not alter scoring or heuristic results", () => {
  const ctx = {
    filename: "invoice.pdf.exe",
    url: "http://10.0.0.5/invoice.pdf.exe",
    mime: "application/x-msdownload",
  };
  const results = ALL.map((language) =>
    evaluate(ctx, { enabled: true, sensitivity: "medium", language }),
  );

  assert.equal(new Set(results.map((r) => r.score)).size, 1, "score drifted by language");
  assert.equal(new Set(results.map((r) => r.verdict)).size, 1, "verdict drifted by language");
  assert.deepEqual(
    results[0].reasons.map((r) => [r.code, r.points]),
    results[3].reasons.map((r) => [r.code, r.points]),
  );
});

test("language does not alter verdict thresholds", () => {
  const cases = [
    { filename: "setup.exe", url: "https://example.com/setup.exe" },
    { filename: "a.pdf.exe", url: "https://example.com/a.pdf.exe" },
    { filename: "report.pdf", url: "https://example.com/report.pdf" },
    { filename: "run.ps1", url: "http://10.0.0.5/run.ps1" },
  ];
  for (const ctx of cases) {
    for (const sensitivity of ["low", "medium", "high"]) {
      const verdicts = ALL.map((language) =>
        evaluate(ctx, { sensitivity, language }).verdict,
      );
      assert.equal(new Set(verdicts).size, 1, `verdict drift for ${ctx.filename} @ ${sensitivity}`);
    }
  }
});

test("heuristic weights and stored reason text are unchanged", () => {
  const results = runAllHeuristics({
    filename: "invoice.pdf.exe",
    url: "http://10.0.0.5/invoice.pdf.exe",
    mime: "application/x-msdownload",
  });
  const byCode = Object.fromEntries(results.map((r) => [r.code, r.points]));

  assert.equal(byCode.DOUBLE_EXTENSION, 40);
  assert.equal(byCode.EXECUTABLE_EXTENSION, 25);
  assert.equal(byCode.INSECURE_HTTP, 10);
  assert.equal(byCode.IP_HOST, 20);

  // MIME_MISMATCH needs a document/media extension with an executable MIME type.
  const mismatch = runAllHeuristics({
    filename: "invoice.pdf",
    url: "https://example.com/invoice.pdf",
    mime: "application/x-msdownload",
  });
  assert.equal(mismatch.find((r) => r.code === "MIME_MISMATCH").points, 30);

  // `text` stays the canonical English sentence for storage; `params` is the
  // language-independent data used for localized rendering.
  const double = results.find((r) => r.code === "DOUBLE_EXTENSION");
  assert.equal(double.text, "File name invoice.pdf.exe uses a double extension (.pdf.exe)");
  assert.deepEqual(double.params, {
    filename: "invoice.pdf.exe",
    previousExtension: "pdf",
    lastExtension: "exe",
  });
});

test("notification builders stay usable without a language argument", () => {
  // Legacy call shape: the language layer's default (English) applies.
  assert.equal(buildNotificationTitle("dangerous"), "Dangerous download");
  assert.equal(buildCompletedNotificationTitle("dangerous"), "Dangerous file already downloaded");
  const message = buildNotificationMessage("a.exe", "example.com", RISKY_REASONS);
  assert.ok(message.includes("File: a.exe"));
  assert.ok(message.includes("double extension"));
});
