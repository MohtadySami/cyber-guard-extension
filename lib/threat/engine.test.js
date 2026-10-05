// Threat engine + provider abstraction.
//
// The security-critical property under test: a provider can never change a
// decision. An unavailable, throwing, slow, or malformed provider must leave the
// verdict exactly as local heuristics computed it.

import test from "node:test";
import assert from "node:assert/strict";

import { evaluate } from "../scoring.js";
import {
  PROVIDER_VERDICTS,
  normalizeProviderResult,
  buildProviderContext,
  createNullProvider,
  createLocalProvider,
  selectProvider,
} from "./provider.js";
import {
  THREAT_STATES,
  assess,
  buildAssessment,
  stateForLocalVerdict,
  stateMessageKey,
} from "./engine.js";

const DANGEROUS_CTX = {
  filename: "invoice.pdf.exe",
  url: "http://10.0.0.5/invoice.pdf.exe",
  mime: "application/octet-stream",
};
const SAFE_CTX = {
  filename: "report.pdf",
  url: "https://example.com/report.pdf",
  mime: "application/pdf",
};
const SETTINGS = { enabled: true, sensitivity: "medium" };

/** Provider that always returns a fixed verdict. */
function fixedProvider(verdict, extra = {}) {
  return {
    id: "fixed",
    available: true,
    async query() {
      return { verdict, ...extra };
    },
  };
}

// --- Normalization

test("normalizeProviderResult accepts every canonical verdict", () => {
  for (const verdict of Object.values(PROVIDER_VERDICTS)) {
    assert.equal(normalizeProviderResult({ verdict }).verdict, verdict);
  }
});

test("normalizeProviderResult maps junk to unavailable", () => {
  for (const junk of [null, undefined, 42, "malicious", {}, { verdict: "maybe" }, { verdict: 7 }]) {
    assert.equal(normalizeProviderResult(junk).verdict, PROVIDER_VERDICTS.UNAVAILABLE);
  }
});

test("normalizeProviderResult accepts a case-insensitive verdict", () => {
  assert.equal(normalizeProviderResult({ verdict: "MALICIOUS" }).verdict, "malicious");
});

test("normalizeProviderResult keeps only well-formed signals", () => {
  const result = normalizeProviderResult({
    verdict: "malicious",
    signals: [
      { code: "GOOD", points: 10 },
      { code: "", points: 5 },
      null,
      "nope",
      { points: 1 },
      { code: "NEG", points: -5 },
      { code: "NAN", points: Number.NaN },
    ],
  });
  assert.equal(result.signals.length, 3);
  assert.deepEqual(result.signals[0], { code: "GOOD", points: 10 });
  assert.equal(result.signals[2].points, 0, "NaN points must normalize to 0");
});

test("normalizeProviderResult freezes its result", () => {
  const result = normalizeProviderResult({ verdict: "malicious" });
  assert.equal(Object.isFrozen(result), true);
});

test("buildProviderContext exposes only name, url and mime", () => {
  const context = buildProviderContext({
    filename: "a.exe",
    url: "http://a/a.exe",
    finalUrl: "http://a/final.exe",
    mime: "application/x-msdownload",
    // A provider must never receive these:
    fileContents: "MZ...",
    downloadId: 42,
    referrer: "https://secret.example/page",
  });
  assert.deepEqual(Object.keys(context).sort(), ["filename", "mime", "url"]);
  assert.equal(context.url, "http://a/final.exe");
  assert.equal("fileContents" in context, false);
  assert.equal("downloadId" in context, false);
});

test("buildProviderContext tolerates malformed input", () => {
  assert.deepEqual(buildProviderContext(null), { filename: "", url: "", mime: "" });
  assert.deepEqual(buildProviderContext("nope"), { filename: "", url: "", mime: "" });
});

// --- Bundled providers

test("the null provider always reports unavailable", async () => {
  const provider = createNullProvider();
  assert.equal(provider.available, false);
  const result = await provider.query(DANGEROUS_CTX);
  assert.equal(result.verdict, PROVIDER_VERDICTS.UNAVAILABLE);
  assert.equal(result.error, "no provider configured");
});

test("the local provider restates the local verdict", async () => {
  const provider = createLocalProvider({ evaluate });
  assert.equal((await provider.query(DANGEROUS_CTX)).verdict, PROVIDER_VERDICTS.MALICIOUS);
  assert.equal((await provider.query(SAFE_CTX)).verdict, PROVIDER_VERDICTS.SAFE);
});

test("the local provider reports unavailable when its evaluator throws", async () => {
  const provider = createLocalProvider({
    evaluate: () => {
      throw new Error("boom");
    },
  });
  assert.equal((await provider.query(DANGEROUS_CTX)).verdict, PROVIDER_VERDICTS.UNAVAILABLE);
});

test("the local provider reports unavailable with no evaluator", async () => {
  assert.equal(
    (await createLocalProvider({}).query(DANGEROUS_CTX)).verdict,
    PROVIDER_VERDICTS.UNAVAILABLE,
  );
  assert.equal(
    (await createLocalProvider(null).query(DANGEROUS_CTX)).verdict,
    PROVIDER_VERDICTS.UNAVAILABLE,
  );
});

test("selectProvider returns the null provider unless a real provider is registered", () => {
  assert.equal(selectProvider({}).id, "null");
  assert.equal(selectProvider({ threatIntel: true }).id, "null", "no provider ships in 0.2.0");
  // Even with threatIntel on, an empty registry must not yield a live provider.
  assert.equal(selectProvider({ threatIntel: true }, {}).id, "null");
  assert.equal(selectProvider({ threatIntel: true }, { http: {} }).id, "null");
});

test("selectProvider uses a registered provider only when explicitly enabled", () => {
  const registry = { http: fixedProvider(PROVIDER_VERDICTS.MALICIOUS) };
  assert.equal(selectProvider({ threatIntel: true }, registry).id, "fixed");
  assert.equal(selectProvider({ threatIntel: false }, registry).id, "null");
});

// --- Threat states

test("only a dangerous local verdict produces the THREAT state", () => {
  assert.equal(stateForLocalVerdict("dangerous"), THREAT_STATES.THREAT);
  // A suspicious file must NOT light up the crimson threat state.
  assert.equal(stateForLocalVerdict("suspicious"), THREAT_STATES.SECURE);
  assert.equal(stateForLocalVerdict("safe"), THREAT_STATES.SECURE);
});

test("buildAssessment maps verdicts to states and keeps the canonical verdict", () => {
  assert.equal(buildAssessment({ verdict: "dangerous", score: 95, reasons: [] }).state, THREAT_STATES.THREAT);
  assert.equal(buildAssessment({ verdict: "suspicious", score: 40, reasons: [] }).state, THREAT_STATES.SECURE);
  assert.equal(buildAssessment({ verdict: "safe", score: 0, reasons: [] }).state, THREAT_STATES.SECURE);
});

test("buildAssessment tolerates malformed local results", () => {
  for (const bad of [null, undefined, {}, "nonsense", 42]) {
    const assessment = buildAssessment(bad);
    assert.equal(assessment.finalVerdict, "safe");
    assert.equal(assessment.state, THREAT_STATES.SECURE);
    assert.equal(assessment.score, 0);
    assert.deepEqual(assessment.reasons, []);
  }
});

test("stateMessageKey maps every state to a message key", () => {
  assert.equal(stateMessageKey(THREAT_STATES.SECURE), "stateSecure");
  assert.equal(stateMessageKey(THREAT_STATES.ANALYZING), "stateAnalyzing");
  assert.equal(stateMessageKey(THREAT_STATES.THREAT), "stateThreat");
  assert.equal(stateMessageKey("nonsense"), "stateSecure");
});

// --- assess(): the provider can never change a decision

test("assess without a provider returns the local verdict", async () => {
  const assessment = await assess(DANGEROUS_CTX, SETTINGS, { evaluate });
  assert.equal(assessment.finalVerdict, "dangerous");
  assert.equal(assessment.state, THREAT_STATES.THREAT);
  assert.equal(assessment.providerAvailable, false);
});

test("a MALICIOUS provider cannot escalate a SAFE local result", async () => {
  const assessment = await assess(SAFE_CTX, SETTINGS, {
    evaluate,
    provider: fixedProvider(PROVIDER_VERDICTS.MALICIOUS),
  });
  assert.equal(assessment.finalVerdict, "safe", "provider escalated a safe download");
  assert.equal(assessment.state, THREAT_STATES.SECURE, "threat state shown without a dangerous verdict");
  // The provider verdict is still recorded for display/diagnostics.
  assert.equal(assessment.provider.verdict, PROVIDER_VERDICTS.MALICIOUS);
  assert.equal(assessment.providerAvailable, true);
});

test("a SUSPICIOUS provider cannot escalate a SAFE local result", async () => {
  const assessment = await assess(SAFE_CTX, SETTINGS, {
    evaluate,
    provider: fixedProvider(PROVIDER_VERDICTS.SUSPICIOUS),
  });
  assert.equal(assessment.finalVerdict, "safe");
  assert.equal(assessment.state, THREAT_STATES.SECURE);
});

test("a SAFE provider cannot downgrade a DANGEROUS local result", async () => {
  const assessment = await assess(DANGEROUS_CTX, SETTINGS, {
    evaluate,
    provider: fixedProvider(PROVIDER_VERDICTS.SAFE),
  });
  assert.equal(assessment.finalVerdict, "dangerous", "provider downgraded a dangerous verdict");
  assert.equal(assessment.state, THREAT_STATES.THREAT);
});

test("a throwing provider is treated as unavailable, not as a threat", async () => {
  const assessment = await assess(SAFE_CTX, SETTINGS, {
    evaluate,
    provider: {
      id: "boom",
      available: true,
      async query() {
        throw new Error("network down");
      },
    },
  });
  assert.equal(assessment.finalVerdict, "safe");
  assert.equal(assessment.providerAvailable, false);
  assert.equal(assessment.provider.error, "provider threw");
});

test("a provider that never resolves is abandoned on timeout", async () => {
  const started = Date.now();
  const assessment = await assess(SAFE_CTX, SETTINGS, {
    evaluate,
    provider: { id: "hang", available: true, query: () => new Promise(() => {}) },
    timeoutMs: 40,
  });
  assert.ok(Date.now() - started < 2000, "engine waited on a hanging provider");
  assert.equal(assessment.finalVerdict, "safe", "timeout escalated a safe result");
  assert.equal(assessment.providerAvailable, false);
  assert.equal(assessment.provider.error, "provider timed out");
});

test("a slow-but-answering provider is still used", async () => {
  const assessment = await assess(DANGEROUS_CTX, SETTINGS, {
    evaluate,
    provider: {
      id: "slow",
      available: true,
      async query() {
        await new Promise((r) => setTimeout(r, 20));
        return { verdict: "malicious" };
      },
    },
    timeoutMs: 500,
  });
  assert.equal(assessment.providerAvailable, true);
  assert.equal(assessment.finalVerdict, "dangerous");
});

test("a hanging provider cannot stall a safe download past the local verdict", async () => {
  // The download is paused while assessment runs, so the timeout must fire.
  const assessment = await assess(SAFE_CTX, SETTINGS, {
    evaluate,
    provider: { id: "hang", available: true, query: () => new Promise(() => {}) },
    timeoutMs: 20,
  });
  assert.equal(assessment.state, "secure");
  assert.equal(assessment.score, 0);
});

test("a provider returning junk yields an unavailable result and no escalation", async () => {
  for (const junk of [null, undefined, "malicious", 42, { verdict: "totally-malicious" }]) {
    const assessment = await assess(SAFE_CTX, SETTINGS, {
      evaluate,
      provider: { id: "junk", available: true, async query() { return junk; } },
    });
    assert.equal(assessment.finalVerdict, "safe", `junk ${JSON.stringify(junk)} escalated`);
    assert.equal(assessment.providerAvailable, false);
  }
});

test("an analysis error still fails open to safe", async () => {
  const assessment = await assess(DANGEROUS_CTX, SETTINGS, {
    evaluate: () => {
      throw new Error("heuristic explosion");
    },
  });
  assert.equal(assessment.finalVerdict, "safe");
  assert.equal(assessment.state, THREAT_STATES.SECURE);
});

test("assess without an evaluator returns a safe assessment rather than throwing", async () => {
  for (const deps of [undefined, null, {}, { evaluate: null }]) {
    const assessment = await assess(DANGEROUS_CTX, SETTINGS, deps);
    assert.equal(assessment.finalVerdict, "safe");
  }
});

test("assess never rejects, whatever the provider does", async () => {
  const hostile = {
    id: "hostile",
    available: true,
    query() {
      throw new Error("sync throw");
    },
  };
  await assert.doesNotReject(() => assess(DANGEROUS_CTX, SETTINGS, { evaluate, provider: hostile }));
});

test("the real local provider does not change any local verdict", async () => {
  const cases = [DANGEROUS_CTX, SAFE_CTX];
  for (const ctx of cases) {
    const withoutProvider = await assess(ctx, SETTINGS, { evaluate });
    const withProvider = await assess(ctx, SETTINGS, {
      evaluate,
      provider: createLocalProvider({ evaluate }),
    });
    assert.equal(withProvider.finalVerdict, withoutProvider.finalVerdict);
    assert.equal(withProvider.state, withoutProvider.state);
    assert.equal(withProvider.score, withoutProvider.score);
  }
});

test("threat assessment is frozen", async () => {
  const assessment = await assess(DANGEROUS_CTX, SETTINGS, { evaluate });
  assert.equal(Object.isFrozen(assessment), true);
});

test("provider availability is reported honestly for the UI", async () => {
  const off = await assess(SAFE_CTX, SETTINGS, { evaluate });
  assert.equal(off.providerAvailable, false, "0.2.0 ships no provider, so this must be false");

  const on = await assess(SAFE_CTX, SETTINGS, {
    evaluate,
    provider: fixedProvider(PROVIDER_VERDICTS.SAFE),
  });
  assert.equal(on.providerAvailable, true);
});
