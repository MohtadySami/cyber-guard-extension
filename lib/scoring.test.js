import test from "node:test";
import assert from "node:assert/strict";

import {
  SCORING_CONSTANTS,
  computeScore,
  getVerdict,
  isTrustedHost,
  topReasons,
  evaluate,
} from "./scoring.js";

test("getVerdict - medium boundaries", () => {
  assert.equal(getVerdict(29, "medium"), "safe");
  assert.equal(getVerdict(30, "medium"), "suspicious");
  assert.equal(getVerdict(59, "medium"), "suspicious");
  assert.equal(getVerdict(60, "medium"), "dangerous");
});

test("getVerdict - low boundaries", () => {
  assert.equal(getVerdict(39, "low"), "safe");
  assert.equal(getVerdict(40, "low"), "suspicious");
  assert.equal(getVerdict(69, "low"), "suspicious");
  assert.equal(getVerdict(70, "low"), "dangerous");
});

test("getVerdict - high boundaries", () => {
  assert.equal(getVerdict(19, "high"), "safe");
  assert.equal(getVerdict(20, "high"), "suspicious");
  assert.equal(getVerdict(49, "high"), "suspicious");
  assert.equal(getVerdict(50, "high"), "dangerous");
});

test("getVerdict - unknown sensitivity falls back to medium", () => {
  assert.equal(getVerdict(29, "unknown"), "safe");
  assert.equal(getVerdict(30, "unknown"), "suspicious");
  assert.equal(getVerdict(60, "unknown"), "dangerous");
});

test("computeScore - caps at 100", () => {
  const reasons = [
    { code: "A", points: 40 },
    { code: "B", points: 50 },
    { code: "C", points: 30 },
    { code: "D", points: 25 },
  ];
  assert.equal(computeScore(reasons), 100);
});

test("computeScore - empty reasons gives 0", () => {
  assert.equal(computeScore([]), 0);
});

test("computeScore - ignores garbage points", () => {
  const reasons = [
    { code: "A", points: -10 },
    { code: "B", points: null },
    { code: "C", points: "50" },
    { code: "D", points: 15 },
  ];
  assert.equal(computeScore(reasons), 15);
});

test("setup.exe over https gives 25, safe", () => {
  const v = evaluate({ filename: "setup.exe", finalUrl: "https://example.com/setup.exe" }, { sensitivity: "medium" });
  assert.equal(v.score, 25);
  assert.equal(v.verdict, "safe");
});

test("setup.exe over http from IP gives 55, suspicious (medium)", () => {
  const v = evaluate(
    { filename: "setup.exe", finalUrl: "http://127.0.0.1:8000/setup.exe" },
    { sensitivity: "medium" },
  );
  assert.equal(v.score, 55);
  assert.equal(v.verdict, "suspicious");
});

test("invoice.pdf.exe over http from IP gives dangerous", () => {
  const v = evaluate(
    { filename: "invoice.pdf.exe", finalUrl: "http://127.0.0.1:8000/invoice.pdf.exe" },
    { sensitivity: "medium" },
  );
  assert.equal(v.score, 95); // 40+25+10+20
  assert.equal(v.verdict, "dangerous");
});

test("isTrustedHost - exact match", () => {
  assert.equal(isTrustedHost("example.com", ["example.com"]), true);
});

test("isTrustedHost - subdomain match", () => {
  assert.equal(isTrustedHost("sub.example.com", ["example.com"]), true);
});

test("isTrustedHost - evil domain does not match", () => {
  assert.equal(isTrustedHost("evilpaypal.com", ["paypal.com"]), false);
});

test("isTrustedHost - case insensitive and trimmed", () => {
  assert.equal(isTrustedHost("Example.COM", [" PAYPAL.COM "]), false);
  assert.equal(isTrustedHost("sub.paypal.com", [" PAYPAL.COM "]), true);
});

test("trusted domain with hard signal overrides trust", () => {
  const v = evaluate(
    { filename: "invoice.pdf.exe", finalUrl: "http://127.0.0.1:8000/invoice.pdf.exe" },
    { sensitivity: "medium", trustedDomains: ["127.0.0.1"] },
  );
  // Hard signals present (DOUBLE_EXTENSION) so trust is not applied; score is 95
  assert.equal(v.score, 95);
  assert.equal(v.verdict, "dangerous");
  assert.ok(v.reasons.some((r) => r.code === "DOUBLE_EXTENSION"));
});

test("trusted domain without hard signal gives safe with TRUSTED_DOMAIN reason", () => {
  const v = evaluate(
    { filename: "report.pdf", finalUrl: "https://trusted.example.com/report.pdf" },
    { sensitivity: "medium", trustedDomains: ["trusted.example.com"] },
  );
  assert.equal(v.score, 0);
  assert.equal(v.verdict, "safe");
  assert.equal(v.reasons.length, 1);
  assert.equal(v.reasons[0].code, "TRUSTED_DOMAIN");
});

test("reasons sorted by points descending", () => {
  const v = evaluate(
    { filename: "invoice.pdf.exe", finalUrl: "http://127.0.0.1:8000/invoice.pdf.exe" },
    { sensitivity: "medium" },
  );
  const pts = v.reasons.map((r) => r.points);
  for (let i = 1; i < pts.length; i++) {
    assert.ok(pts[i - 1] >= pts[i]);
  }
});

test("topReasons skips 0-point entries", () => {
  const v = {
    reasons: [
      { code: "A", points: 40 },
      { code: "TRUSTED_DOMAIN", points: 0 },
      { code: "B", points: 20 },
      { code: "C", points: 10 },
    ],
  };
  const top = topReasons(v, 3);
  assert.equal(top.length, 3);
  assert.equal(top[0].code, "A");
  assert.equal(top[1].code, "B");
  assert.equal(top[2].code, "C");
});
