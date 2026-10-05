// Threat engine: combines local heuristics with optional provider intelligence
// into a single normalized threat state that the UI renders.
//
// INVARIANT (security-critical): the provider can never change a decision.
// `finalVerdict` is derived from the LOCAL verdict alone. A provider may add
// corroboration, but a safe local result is never escalated, and an unavailable
// provider is indistinguishable from having no provider at all.

import { PROVIDER_VERDICTS, normalizeProviderResult } from "./provider.js";

/** Visual threat states rendered by the popup. */
export const THREAT_STATES = Object.freeze({
  SECURE: "secure",
  ANALYZING: "analyzing",
  THREAT: "threat",
});

/**
 * The normalized result the UI consumes.
 * @typedef {Object} ThreatAssessment
 * @property {string} state - One of THREAT_STATES.
 * @property {string} finalVerdict - Canonical safe | suspicious | dangerous.
 * @property {number} score - Local heuristic score, 0-100.
 * @property {Array} reasons - Local heuristic reasons (language-independent).
 * @property {Object} provider - Normalized provider result.
 * @property {boolean} providerAvailable - Whether a provider produced a verdict.
 */

/**
 * Map a local verdict onto a visual threat state.
 *
 * The crimson THREAT state requires a confirmed `dangerous` local verdict,
 * never merely a suspicious file name.
 *
 * @param {string} verdict - Canonical local verdict.
 * @returns {string} One of THREAT_STATES.
 */
export function stateForLocalVerdict(verdict) {
  return verdict === "dangerous" ? THREAT_STATES.THREAT : THREAT_STATES.SECURE;
}

/**
 * Builds a threat assessment from a local evaluation result.
 *
 * @param {{verdict: string, score: number, reasons: Array}} local - Local result.
 * @param {unknown} [providerResult] - Optional provider output.
 * @returns {ThreatAssessment} The normalized assessment.
 */
export function buildAssessment(local, providerResult) {
  const safeLocal = local && typeof local === "object" ? local : {};
  const verdict =
    safeLocal.verdict === "dangerous" || safeLocal.verdict === "suspicious"
      ? safeLocal.verdict
      : "safe";
  const provider = normalizeProviderResult(providerResult);
  const providerAvailable = provider.verdict !== PROVIDER_VERDICTS.UNAVAILABLE;

  return Object.freeze({
    state: stateForLocalVerdict(verdict),
    finalVerdict: verdict,
    score: Number.isFinite(safeLocal.score) ? safeLocal.score : 0,
    reasons: Array.isArray(safeLocal.reasons) ? safeLocal.reasons : [],
    provider,
    providerAvailable,
  });
}

/**
 * How long a provider lookup may take before it is abandoned.
 *
 * The download is paused while this runs, so a hanging provider must not be
 * able to stall the pipeline. On timeout the provider is treated as
 * unavailable, which leaves the local verdict untouched.
 */
export const PROVIDER_TIMEOUT_MS = 1500;

/**
 * Races a provider lookup against a timeout.
 *
 * @param {Promise<unknown>} promise - The provider lookup.
 * @param {number} timeoutMs - Abandon the lookup after this long.
 * @returns {Promise<{timedOut: boolean, value?: unknown}>} The outcome.
 */
async function withTimeout(promise, timeoutMs) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ timedOut: true }), timeoutMs);
  });
  try {
    const settled = await Promise.race([
      promise.then((value) => ({ timedOut: false, value })),
      timeout,
    ]);
    return settled;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Runs the engine: local evaluation plus an optional provider lookup.
 *
 * Never throws. A provider that rejects, times out, or returns junk yields an
 * assessment identical to the local-only one.
 *
 * @param {object} ctx - Download context for local heuristics.
 * @param {object} settings - Current settings.
 * @param {{evaluate: Function, provider?: object, timeoutMs?: number}} deps - Injected dependencies.
 * @returns {Promise<ThreatAssessment>} The assessment.
 */
export async function assess(ctx, settings, deps) {
  const evaluate = deps && typeof deps.evaluate === "function" ? deps.evaluate : null;
  if (!evaluate) {
    return buildAssessment({ verdict: "safe", score: 0, reasons: [] }, undefined);
  }

  let local;
  try {
    local = evaluate(ctx, settings);
  } catch {
    // Analysis errors fail open, exactly as in 0.1.x.
    return buildAssessment({ verdict: "safe", score: 0, reasons: [] }, undefined);
  }

  const provider = deps.provider;
  if (!provider || typeof provider.query !== "function") {
    return buildAssessment(local, undefined);
  }

  const timeoutMs =
    deps.timeoutMs === undefined ? PROVIDER_TIMEOUT_MS : deps.timeoutMs;

  let providerResult;
  try {
    const outcome = await withTimeout(Promise.resolve().then(() => provider.query(ctx)), timeoutMs);
    providerResult = outcome.timedOut
      ? { verdict: PROVIDER_VERDICTS.UNAVAILABLE, error: "provider timed out" }
      : outcome.value;
  } catch {
    // A throwing provider is an unavailable provider, never a threat.
    providerResult = { verdict: PROVIDER_VERDICTS.UNAVAILABLE, error: "provider threw" };
  }

  return buildAssessment(local, providerResult);
}

/**
 * Maps a threat state onto its catalogue key.
 *
 * @param {string} state - One of THREAT_STATES.
 * @returns {string} The message key.
 */
export function stateMessageKey(state) {
  if (state === THREAT_STATES.THREAT) {
    return "stateThreat";
  }
  if (state === THREAT_STATES.ANALYZING) {
    return "stateAnalyzing";
  }
  return "stateSecure";
}
