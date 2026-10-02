import test from "node:test";
import assert from "node:assert/strict";

import {
  getBaseName,
  getExtensions,
  getHostname,
  resolveFilename,
  checkScriptExtension,
  checkExecutableExtension,
  checkContainerExtension,
  checkMacroDocument,
  checkDoubleExtension,
  checkRtloCharacter,
  checkTrailingSpacesOrDots,
  checkMimeMismatch,
  checkInsecureHttp,
  checkIpHost,
  checkSuspiciousTld,
  checkPunycodeHost,
  checkLongRedirectChain,
  checkLookalikeDomain,
  runAllHeuristics,
} from "./heuristics.js";

test("getBaseName - handles standard cases", () => {
  assert.equal(getBaseName("invoice.pdf.exe"), "invoice.pdf.exe");
  assert.equal(getBaseName("path/to/file.txt"), "file.txt");
  assert.equal(getBaseName("path\\to\\file.txt"), "file.txt");
  assert.equal(getBaseName("/absolute/path/setup.exe"), "setup.exe");
  assert.equal(getBaseName(""), "");
  assert.equal(getBaseName(null), "");
  assert.equal(getBaseName(undefined), "");
});

test("getExtensions - returns lowercase extensions in order", () => {
  assert.deepEqual(getExtensions("a.pdf.exe"), ["pdf", "exe"]);
  assert.deepEqual(getExtensions("FILE.PDF.EXE"), ["pdf", "exe"]);
  assert.deepEqual(getExtensions("report.pdf"), ["pdf"]);
  assert.deepEqual(getExtensions("setup"), []);
  assert.deepEqual(getExtensions(""), []);
});
test("getHostname - safely parses URLs", () => {
  assert.equal(getHostname("https://example.com/file.pdf"), "example.com");
  assert.equal(getHostname("http://127.0.0.1:8000/download"), "127.0.0.1");
  assert.equal(getHostname("https://subdomain.example.co.uk/path"), "subdomain.example.co.uk");
  assert.equal(getHostname("invalid-url"), "");
  assert.equal(getHostname(""), "");
  assert.equal(getHostname(null), "");
});

test("resolveFilename - resolves with fallbacks", () => {
  assert.equal(resolveFilename({ filename: "report.pdf" }), "report.pdf");
  assert.equal(resolveFilename({ filename: "path/to/report.pdf" }), "report.pdf");
  assert.equal(resolveFilename({ finalUrl: "https://example.com/downloads/invoice.pdf" }), "invoice.pdf");
  assert.equal(resolveFilename({ url: "https://example.com/file.txt" }), "file.txt");
  assert.equal(resolveFilename({ finalUrl: "https://example.com/downloads/test.pdf" }), "test.pdf");
  assert.equal(resolveFilename({}), "");
  assert.equal(resolveFilename(null), "");
});

test("checkScriptExtension - positive case", () => {
  const result = checkScriptExtension({ filename: "script.ps1" });
  assert.ok(result);
  assert.equal(result.code, "SCRIPT_EXTENSION");
  assert.equal(result.points, 35);
  assert.ok(result.text.includes("script.ps1"));
});

test("checkScriptExtension - negative case", () => {
  assert.equal(checkScriptExtension({ filename: "document.pdf" }), null);
});

test("checkScriptExtension - empty input", () => {
  assert.equal(checkScriptExtension({}), null);
  assert.equal(checkScriptExtension(null), null);
});
test("checkExecutableExtension - positive case", () => {
  const result = checkExecutableExtension({ filename: "setup.exe" });
  assert.ok(result);
  assert.equal(result.code, "EXECUTABLE_EXTENSION");
  assert.equal(result.points, 25);
});
test("checkExecutableExtension - negative case", () => {
  assert.equal(checkExecutableExtension({ filename: "report.pdf" }), null);
});
test("checkExecutableExtension - empty input", () => {
  assert.equal(checkExecutableExtension({}), null);
});
test("checkContainerExtension - positive case", () => {
  const result = checkContainerExtension({ filename: "archive.zip" });
  assert.ok(result);
  assert.equal(result.code, "CONTAINER_EXTENSION");
  assert.equal(result.points, 10);
});
test("checkContainerExtension - negative case", () => {
  assert.equal(checkContainerExtension({ filename: "file.txt" }), null);
});
test("checkContainerExtension - empty input", () => {
  assert.equal(checkContainerExtension({}), null);
});
test("checkMacroDocument - positive case", () => {
  const result = checkMacroDocument({ filename: "workbook.xlsm" });
  assert.ok(result);
  assert.equal(result.code, "MACRO_DOCUMENT");
  assert.equal(result.points, 15);
});
test("checkMacroDocument - negative case", () => {
  assert.equal(checkMacroDocument({ filename: "workbook.xlsx" }), null);
});
test("checkMacroDocument - empty input", () => {
  assert.equal(checkMacroDocument({}), null);
});
test("checkDoubleExtension - positive case", () => {
  const result = checkDoubleExtension({ filename: "invoice.pdf.exe" });
  assert.ok(result);
  assert.equal(result.code, "DOUBLE_EXTENSION");
  assert.equal(result.points, 40);
  assert.ok(result.text.includes("pdf.exe"));
});
test("checkDoubleExtension - negative case", () => {
  assert.equal(checkDoubleExtension({ filename: "setup.exe" }), null);
  assert.equal(checkDoubleExtension({ filename: "report.pdf" }), null);
});
test("checkDoubleExtension - empty input", () => {
  assert.equal(checkDoubleExtension({}), null);
});
test("checkRtloCharacter - positive case", () => {
  const result = checkRtloCharacter({ filename: "photo\u202Egpj.exe" });
  assert.ok(result);
  assert.equal(result.code, "RTLO_CHARACTER");
  assert.equal(result.points, 50);
});
test("checkRtloCharacter - negative case", () => {
  assert.equal(checkRtloCharacter({ filename: "photogpj.exe" }), null);
});
test("checkRtloCharacter - empty input", () => {
  assert.equal(checkRtloCharacter({}), null);
});
test("checkTrailingSpacesOrDots - positive case with spaces", () => {
  const result = checkTrailingSpacesOrDots({ filename: "report.pdf     .exe" });
  assert.ok(result);
  assert.equal(result.code, "TRAILING_SPACES_OR_DOTS");
  assert.equal(result.points, 20);
});
test("checkTrailingSpacesOrDots - positive case with many spaces", () => {
  const result = checkTrailingSpacesOrDots({ filename: "file    .txt" });
  assert.ok(result);
});
test("checkTrailingSpacesOrDots - negative case", () => {
  assert.equal(checkTrailingSpacesOrDots({ filename: "report.pdf" }), null);
});
test("checkTrailingSpacesOrDots - empty input", () => {
  assert.equal(checkTrailingSpacesOrDots({}), null);
});
test("checkMimeMismatch - positive case", () => {
  const result = checkMimeMismatch({
    filename: "document.pdf",
    mime: "application/x-msdownload",
  });
  assert.ok(result);
  assert.equal(result.code, "MIME_MISMATCH");
  assert.equal(result.points, 30);
});
test("checkMimeMismatch - negative case", () => {
  assert.equal(
    checkMimeMismatch({ filename: "document.pdf", mime: "application/pdf" }),
    null,
  );
  assert.equal(
    checkMimeMismatch({ filename: "document.pdf", mime: "application/octet-stream" }),
    null,
  );
});
test("checkMimeMismatch - empty input", () => {
  assert.equal(checkMimeMismatch({}), null);
});
test("checkInsecureHttp - positive case", () => {
  const result = checkInsecureHttp({ finalUrl: "http://example.com/file.exe" });
  assert.ok(result);
  assert.equal(result.code, "INSECURE_HTTP");
  assert.equal(result.points, 10);
});
test("checkInsecureHttp - negative case", () => {
  assert.equal(checkInsecureHttp({ finalUrl: "https://example.com/file.exe" }), null);
});
test("checkInsecureHttp - empty input", () => {
  assert.equal(checkInsecureHttp({}), null);
});
test("checkIpHost - positive case", () => {
  const result = checkIpHost({ finalUrl: "http://127.0.0.1:8000/download" });
  assert.ok(result);
  assert.equal(result.code, "IP_HOST");
  assert.equal(result.points, 20);
});
test("checkIpHost - negative case", () => {
  assert.equal(checkIpHost({ finalUrl: "https://example.com/download" }), null);
});
test("checkIpHost - empty input", () => {
  assert.equal(checkIpHost({}), null);
});

test("checkSuspiciousTld - positive case", () => {
  const result = checkSuspiciousTld({ finalUrl: "https://example.zip/file" });
  assert.ok(result);
  assert.equal(result.code, "SUSPICIOUS_TLD");
  assert.equal(result.points, 10);
});

test("checkSuspiciousTld - negative case", () => {
  assert.equal(checkSuspiciousTld({ finalUrl: "https://example.com/file" }), null);
});

test("checkSuspiciousTld - empty input", () => {
  assert.equal(checkSuspiciousTld({}), null);
});

test("checkPunycodeHost - positive case", () => {
  const result = checkPunycodeHost({ finalUrl: "https://xn--pple-43d.com/file" });
  assert.ok(result);
  assert.equal(result.code, "PUNYCODE_HOST");
  assert.equal(result.points, 15);
});

test("checkPunycodeHost - negative case", () => {
  assert.equal(checkPunycodeHost({ finalUrl: "https://example.com/file" }), null);
});

test("checkPunycodeHost - empty input", () => {
  assert.equal(checkPunycodeHost({}), null);
});

test("runAllHeuristics - invoice.pdf.exe over http from IP gives multiple hits", () => {
  const results = runAllHeuristics({
    filename: "invoice.pdf.exe",
    finalUrl: "http://127.0.0.1:8000/invoice.pdf.exe",
  });

  const codes = results.map((r) => r.code);
  assert.ok(codes.includes("DOUBLE_EXTENSION"));
  assert.ok(codes.includes("EXECUTABLE_EXTENSION"));
  assert.ok(codes.includes("INSECURE_HTTP"));
  assert.ok(codes.includes("IP_HOST"));
});

test("runAllHeuristics - report.pdf over https from normal domain gives no results", () => {
  const results = runAllHeuristics({
    filename: "report.pdf",
    finalUrl: "https://example.com/report.pdf",
  });
  assert.deepEqual(results, []);
});

test("runAllHeuristics - setup.exe over https gives only executable extension", () => {
  const results = runAllHeuristics({
    filename: "setup.exe",
    finalUrl: "https://example.com/setup.exe",
  });
  assert.equal(results.length, 1);
  assert.equal(results[0].code, "EXECUTABLE_EXTENSION");
  assert.equal(results[0].points, 25);
});

test("runAllHeuristics - RTLO in filename gives RTLO_CHARACTER", () => {
  const results = runAllHeuristics({
    filename: "photo\u202Egpj.exe",
    finalUrl: "https://example.com/photo\u202Egpj.exe",
  });
  const codes = results.map((r) => r.code);
  assert.ok(codes.includes("RTLO_CHARACTER"));
  assert.ok(codes.includes("EXECUTABLE_EXTENSION"));
});

test("runAllHeuristics - empty ctx returns empty array", () => {
  assert.deepEqual(runAllHeuristics({}), []);
  assert.deepEqual(runAllHeuristics(null), []);
});

test("runAllHeuristics - handles uppercase extensions", () => {
  const results = runAllHeuristics({
    filename: "FILE.PDF.EXE",
    finalUrl: "https://example.com/FILE.PDF.EXE",
  });
  const codes = results.map((r) => r.code);
  assert.ok(codes.includes("DOUBLE_EXTENSION"));
  assert.ok(codes.includes("EXECUTABLE_EXTENSION"));
});

test("runAllHeuristics - null ctx returns empty array without throwing", () => {
  assert.deepEqual(runAllHeuristics(null), []);
});

test("runAllHeuristics - my report (1).pdf over https gives no results", () => {
  const results = runAllHeuristics({
    filename: "my report (1).pdf",
    finalUrl: "https://example.com/my%20report%20(1).pdf",
  });
  assert.deepEqual(results, []);
});

test("runAllHeuristics - v1.2.3-setup.exe over https gives only executable extension", () => {
  const results = runAllHeuristics({
    filename: "v1.2.3-setup.exe",
    finalUrl: "https://example.com/v1.2.3-setup.exe",
  });
  assert.equal(results.length, 1);
  assert.equal(results[0].code, "EXECUTABLE_EXTENSION");
  assert.equal(results[0].points, 25);
});

test("runAllHeuristics - file.pdf.EXE gives DOUBLE_EXTENSION and EXECUTABLE_EXTENSION", () => {
  const results = runAllHeuristics({
    filename: "file.pdf.EXE",
    finalUrl: "https://example.com/file.pdf.EXE",
  });
  const codes = results.map((r) => r.code);
  assert.ok(codes.includes("DOUBLE_EXTENSION"));
  assert.ok(codes.includes("EXECUTABLE_EXTENSION"));
});

test("runAllHeuristics - report.pdf     .exe gives TRAILING_SPACES_OR_DOTS and DOUBLE_EXTENSION", () => {
  const results = runAllHeuristics({
    filename: "report.pdf     .exe",
    finalUrl: "https://example.com/report.pdf%20%20%20%20%20.exe",
  });
  const codes = results.map((r) => r.code);
  assert.ok(codes.includes("TRAILING_SPACES_OR_DOTS"));
  assert.ok(codes.includes("DOUBLE_EXTENSION"));
});

test("checkLongRedirectChain - no redirects", () => {
  assert.equal(checkLongRedirectChain({ redirectChain: [] }), null);
  assert.equal(checkLongRedirectChain({}), null);
});

test("checkLongRedirectChain - 3 hops gives short chain", () => {
  const result = checkLongRedirectChain({
    redirectChain: ["a", "b", "c"],
  });
  assert.ok(result);
  assert.equal(result.code, "LONG_REDIRECT_CHAIN");
  assert.equal(result.points, 10);
});

test("checkLongRedirectChain - 5 hops gives long chain", () => {
  const result = checkLongRedirectChain({
    redirectChain: ["a", "b", "c", "d", "e"],
  });
  assert.ok(result);
  assert.equal(result.code, "LONG_REDIRECT_CHAIN");
  assert.equal(result.points, 20);
});

test("checkLookalikeDomain - stub returns null", () => {
  assert.equal(checkLookalikeDomain("example.com"), null);
  assert.equal(checkLookalikeDomain(""), null);
});
