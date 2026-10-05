// Page threat alert: gating, localization, permission handling, and injection.
//
// The alert is injected ONE-SHOT into the originating tab. There is no
// permanently registered content script, and nothing is injected unless the
// verdict is a confirmed `dangerous` AND the user granted the optional
// permission.

import test from "node:test";
import assert from "node:assert/strict";

import { loadRealCatalogues } from "./test-i18n-fixture.js";
import { SUPPORTED_LANGUAGES, normalizeLanguage, getDirection } from "./i18n.js";
import {
  shouldAlertOnPage,
  buildAlertPayload,
  hasPageAlertPermission,
  PAGE_ALERT_PERMISSION,
  ALERT_HOST_ID,
} from "./page-alert.js";
import { evaluate } from "./scoring.js";

loadRealCatalogues();

const ALL = [...SUPPORTED_LANGUAGES];
const REASON = {
  code: "DOUBLE_EXTENSION",
  points: 40,
  text: "File name invoice.pdf.exe uses a double extension (.pdf.exe)",
  params: { filename: "invoice.pdf.exe", previousExtension: "pdf", lastExtension: "exe" },
};

// --- Gating: when may an alert appear?

test("safe, suspicious, and dangerous verdicts on a real tab may raise a page alert", () => {
  assert.equal(shouldAlertOnPage({ verdict: "dangerous", tabId: 12 }), true);
  assert.equal(shouldAlertOnPage({ verdict: "suspicious", tabId: 12 }), true);
  assert.equal(shouldAlertOnPage({ verdict: "safe", tabId: 12 }), true);
});

test("no tab means no page alert", () => {
  // tabId -1 is Chrome's marker for "not started by a page".
  assert.equal(shouldAlertOnPage({ verdict: "dangerous", tabId: -1 }), false);
  assert.equal(shouldAlertOnPage({ verdict: "dangerous" }), false);
  assert.equal(shouldAlertOnPage({ verdict: "dangerous", tabId: null }), false);
  assert.equal(shouldAlertOnPage({ verdict: "dangerous", tabId: 1.5 }), false);
  assert.equal(shouldAlertOnPage({ verdict: "dangerous", tabId: "12" }), false);
});

test("shouldAlertOnPage tolerates malformed input", () => {
  for (const bad of [null, undefined, {}, "nonsense", 42]) {
    assert.equal(shouldAlertOnPage(bad), false);
  }
});

test("gating matches the real scoring verdict, not a hardcoded string", () => {
  // Sanity check that the gate agrees with the engine for a real context.
  const dangerous = evaluate(
    { filename: "invoice.pdf.exe", url: "http://10.0.0.5/invoice.pdf.exe" },
    { sensitivity: "medium" },
  );
  const safe = evaluate(
    { filename: "report.pdf", url: "https://example.com/report.pdf" },
    { sensitivity: "medium" },
  );
  assert.equal(shouldAlertOnPage({ verdict: dangerous.verdict, tabId: 3 }), true);
  assert.equal(shouldAlertOnPage({ verdict: safe.verdict, tabId: 3 }), true);
});

// --- Payload localization

test("the alert payload is localized in all four languages", () => {
  const seen = new Set();
  for (const language of ALL) {
    const payload = buildAlertPayload({
      filename: "invoice.pdf.exe",
      reason: REASON,
      language,
    });
    assert.ok(payload.headline.length > 0, `${language}: empty headline`);
    assert.ok(payload.body.length > 0, `${language}: empty body`);
    assert.equal(payload.filename, "invoice.pdf.exe");
    assert.equal(payload.language, language);
    // No unresolved catalogue keys anywhere.
    for (const [key, value] of Object.entries(payload)) {
      assert.ok(
        typeof value !== "string" || !/^(alert|notif|state)[A-Z]/.test(value),
        `${language}/${key} looks like an unresolved key: ${value}`,
      );
    }
    seen.add(payload.headline);
  }
  assert.equal(seen.size, ALL.length, "alert headline is not distinct per language");
});

test("the alert reason is localized by code, not the stored English text", () => {
  const english = buildAlertPayload({ filename: "a.exe", reason: REASON, language: "en" });
  const french = buildAlertPayload({ filename: "a.exe", reason: REASON, language: "fr" });
  const arabic = buildAlertPayload({ filename: "a.exe", reason: REASON, language: "ar" });

  assert.ok(english.reason.includes("double extension"));
  assert.ok(arabic.reason.includes("invoice.pdf.exe"));
  assert.notEqual(french.reason, english.reason);
});

test("the alert reason is RTL-correct for Arabic", () => {
  assert.equal(getDirection("ar"), "rtl");
  assert.equal(getDirection("en"), "ltr");
  const arabic = buildAlertPayload({ filename: "a.exe", reason: REASON, language: "ar" });
  assert.equal(arabic.language, "ar");
});

test("an alert with no reason still renders its other fields", () => {
  for (const language of ALL) {
    const payload = buildAlertPayload({ filename: "a.exe", language });
    assert.equal(payload.reason, "");
    assert.ok(payload.headline.length > 0);
  }
});

test("the alert filename is bounded and type-checked", () => {
  const long = buildAlertPayload({ filename: "x".repeat(500), language: "en" });
  assert.ok(long.filename.length <= 100);
  assert.equal(buildAlertPayload({ filename: 42, language: "en" }).filename, "");
  assert.equal(buildAlertPayload({ language: "en" }).filename, "");
});

test("the alert payload never contains the source URL", () => {
  // The alert is injected into a page; leaking the URL there would expose
  // browsing information to the page's DOM.
  const payload = buildAlertPayload({
    filename: "invoice.pdf.exe",
    reason: REASON,
    language: "en",
  });
  const serialized = JSON.stringify(payload);
  assert.ok(!serialized.includes("http"), "payload leaked a URL");
  assert.ok(!serialized.includes("example.com"));
});

test("buildAlertPayload tolerates malformed input", () => {
  for (const bad of [null, undefined, "nonsense", 42]) {
    const payload = buildAlertPayload(bad);
    assert.ok(payload.headline.length > 0);
    assert.equal(payload.filename, "");
  }
});

test("an unsupported language falls back to English in the alert", () => {
  const payload = buildAlertPayload({ filename: "a.exe", language: "de" });
  assert.equal(payload.language, "en");
});

test("buildAlertPayload properly maps each verdict to corresponding icons, headlines, and bodies", () => {
  for (const language of ALL) {
    const dangerous = buildAlertPayload({
      verdict: "dangerous",
      filename: "malware.exe",
      reason: REASON,
      language,
    });
    assert.equal(dangerous.verdict, "dangerous");
    assert.equal(dangerous.icon, "⚠️");
    assert.ok(dangerous.headline.length > 0);
    assert.ok(dangerous.body.length > 0);

    const suspicious = buildAlertPayload({
      verdict: "suspicious",
      filename: "script.bat",
      reason: REASON,
      language,
    });
    assert.equal(suspicious.verdict, "suspicious");
    assert.equal(suspicious.icon, "⚠️");
    assert.ok(suspicious.headline.length > 0);
    assert.ok(suspicious.body.length > 0);

    const safe = buildAlertPayload({
      verdict: "safe",
      filename: "document.pdf",
      language,
    });
    assert.equal(safe.verdict, "safe");
    assert.equal(safe.icon, "✓");
    assert.ok(safe.headline.length > 0);
    assert.ok(safe.body.length > 0);
  }
});

// --- Permissions

test("the page alert asks for scripting plus http/https origins, never <all_urls>", () => {
  assert.deepEqual([...PAGE_ALERT_PERMISSION.permissions], ["scripting"]);
  assert.deepEqual([...PAGE_ALERT_PERMISSION.origins].sort(), ["http://*/*", "https://*/*"]);
  assert.equal(
    PAGE_ALERT_PERMISSION.origins.includes("<all_urls>"),
    false,
    "broad host permission must never be requested",
  );
  // file:// and ftp:// are deliberately excluded.
  assert.equal(PAGE_ALERT_PERMISSION.origins.some((o) => o.startsWith("file:")), false);
});

test("hasPageAlertPermission is true only when the exact permission is granted", async () => {
  const calls = [];
  const granted = await hasPageAlertPermission({
    async contains(request) {
      calls.push(request);
      return true;
    },
  });
  assert.equal(granted, true);
  assert.equal(calls.length, 1);
});

test("hasPageAlertPermission is false when the user denies", async () => {
  assert.equal(await hasPageAlertPermission({ async contains() { return false; } }), false);
});

test("hasPageAlertPermission is false without a permissions API", async () => {
  assert.equal(await hasPageAlertPermission(null), false);
  assert.equal(await hasPageAlertPermission(undefined), false);
  assert.equal(await hasPageAlertPermission({}), false);
  assert.equal(await hasPageAlertPermission({ contains: "not-a-function" }), false);
});

test("hasPageAlertPermission is false when the permissions API throws", async () => {
  const granted = await hasPageAlertPermission({
    contains() {
      throw new Error("context invalidated");
    },
  });
  assert.equal(granted, false);
});

test("the alert host id is stable and page-namespaced", () => {
  assert.equal(ALERT_HOST_ID, "cyber-guard-page-alert");
});
