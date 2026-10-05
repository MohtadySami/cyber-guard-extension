import test from "node:test";
import assert from "node:assert/strict";

import { loadRealCatalogues } from "./test-i18n-fixture.js";
import {
  truncateString,
  buildNotificationTitle,
  buildNotificationMessage,
} from "./alert.js";

loadRealCatalogues();

test("truncateString - short strings unchanged", () => {
  assert.equal(truncateString("hello", 10), "hello");
  assert.equal(truncateString("", 5), "");
  assert.equal(truncateString(null, 5), "");
});

test("truncateString - truncates long strings", () => {
  const long = "a".repeat(100);
  const result = truncateString(long, 10);
  assert.equal(result.length, 10);
  assert.ok(result.endsWith("..."));
});

test("buildNotificationTitle - returns correct titles", () => {
  assert.equal(buildNotificationTitle("dangerous", "en"), "Dangerous download");
  assert.equal(buildNotificationTitle("suspicious", "en"), "Suspicious download");
  // Anything that is not `dangerous` presents as suspicious.
  assert.equal(buildNotificationTitle("safe", "en"), "Suspicious download");
});

test("buildNotificationTitle defaults to English when no language is given", () => {
  assert.equal(buildNotificationTitle("dangerous"), "Dangerous download");
});

test("buildNotificationTitle is localized", () => {
  assert.equal(buildNotificationTitle("dangerous", "fr"), "Téléchargement dangereux");
  assert.equal(buildNotificationTitle("suspicious", "es"), "Descarga sospechosa");
  assert.equal(buildNotificationTitle("dangerous", "ar"), "تنزيل خطير");
});

test("buildNotificationMessage - builds message with top reasons", () => {
  // Unknown codes fall back to their stored text, which is what keeps a
  // provider-supplied reason visible even with no catalogue entry.
  const reasons = [
    { code: "A", points: 40, text: "Reason A" },
    { code: "B", points: 20, text: "Reason B" },
    { code: "C", points: 10, text: "Reason C" },
    { code: "D", points: 5, text: "Reason D" },
  ];
  const msg = buildNotificationMessage("file.exe", "example.com", reasons, "en");
  assert.ok(msg.includes("File: file.exe"));
  assert.ok(msg.includes("Source: example.com"));
  assert.ok(msg.includes("Reason A"));
  assert.ok(msg.includes("Reason B"));
  assert.ok(msg.includes("Reason C"));
  assert.ok(!msg.includes("Reason D")); // only top 3
});

test("buildNotificationMessage - known reason codes render localized text", () => {
  const reasons = [
    { code: "EXECUTABLE_EXTENSION", points: 25, text: "English fallback", params: { filename: "a.exe", extension: "exe" } },
  ];
  const english = buildNotificationMessage("a.exe", "example.com", reasons, "en");
  const french = buildNotificationMessage("a.exe", "example.com", reasons, "fr");
  assert.ok(english.includes("executable extension"));
  assert.ok(french.includes("extension exécutable"));
  assert.ok(!french.includes("English fallback"));
});
