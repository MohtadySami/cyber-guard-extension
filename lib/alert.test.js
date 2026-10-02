import test from "node:test";
import assert from "node:assert/strict";

import {
  truncateString,
  buildNotificationTitle,
  buildNotificationMessage,
} from "./alert.js";

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
  assert.equal(buildNotificationTitle("dangerous"), "Dangerous download");
  assert.equal(buildNotificationTitle("suspicious"), "Suspicious download");
  assert.equal(buildNotificationTitle("safe"), "Suspicious download");
});

test("buildNotificationMessage - builds message with top reasons", () => {
  const reasons = [
    { code: "A", points: 40, text: "Reason A" },
    { code: "B", points: 20, text: "Reason B" },
    { code: "C", points: 10, text: "Reason C" },
    { code: "D", points: 5, text: "Reason D" },
  ];
  const msg = buildNotificationMessage("file.exe", "example.com", reasons);
  assert.ok(msg.includes("File: file.exe"));
  assert.ok(msg.includes("Source: example.com"));
  assert.ok(msg.includes("Reason A"));
  assert.ok(msg.includes("Reason B"));
  assert.ok(msg.includes("Reason C"));
  assert.ok(!msg.includes("Reason D")); // only top 3
});
