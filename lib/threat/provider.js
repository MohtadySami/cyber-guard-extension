// Threat-intelligence provider interface.
//
// This module defines the CONTRACT between Cyber Guard's decision engine and any
// external reputation/threat source. It ships with no network implementation:
// the only providers bundled are the local heuristic reader and an explicit
// "disabled" provider. An HTTP provider is intentionally absent (see
// PROJECT_REPORT.md "Threat intelligence" for the legal/architectural reasons).
//
// Design rules:
//   * A provider NEVER influences the final verdict on its own. It can only
//     corroborate what the local heuristics already flagged.
//   * Every failure mode (unavailable, timeout, error, malformed payload)
//     normalizes to `unavailable`, which the engine treats as "no information".
//   * No provider may receive file contents. Context is limited to the file
//     name, URL and MIME type the local analysis already uses.

/** Canonical provider outcomes. */
export const PROVIDER_VERDICTS = Object.freeze({
  SAFE: "safe",
  SUSPICIOUS: "suspicious",
  MALICIOUS: "malicious",
  UNAVAILABLE: "unavailable",
});

/**
 * The normalized result every provider must return.
 * @typedef {Object} ProviderResult
 * @property {string} verdict - One of PROVIDER_VERDICTS.
 * @property {string} [source] - Provider identifier for diagnostics/history.
 * @property {Array<{code: string, points: number}>} [signals] - Provider signals.
 * @property {string} [detail] - Short note (not localized).
 * @property {string} [error] - Failure reason when verdict is `unavailable`.
 */

/** Minimal download context a provider may inspect. No file contents. */
export function buildProviderContext(ctx) {
  const safe = ctx && typeof ctx === "object" ? ctx : {};
  return Object.freeze({
    filename: typeof safe.filename === "string" ? safe.filename : "",
    url:
      typeof safe.finalUrl === "string" && safe.finalUrl
        ? safe.finalUrl
        : typeof safe.url === "string"
          ? safe.url
          : "",
    mime: typeof safe.mime === "string" ? safe.mime : "",
  });
}

/**
 * Normalizes any provider return value into a ProviderResult.
 *
 * Defensive by design: a provider returning junk must never throw and never
 * produce a verdict that could escalate a safe local result.
 *
 * @param {unknown} raw - Whatever the provider returned.
 * @param {string} [source] - Fallback provider identifier.
 * @returns {ProviderResult} A valid, frozen result.
 */
export function normalizeProviderResult(raw, source = "unknown") {
  const fallback = Object.freeze({
    verdict: PROVIDER_VERDICTS.UNAVAILABLE,
    source,
    signals: Object.freeze([]),
  });

  if (!raw || typeof raw !== "object") {
    return fallback;
  }

  const verdict =
    typeof raw.verdict === "string" ? raw.verdict.toLowerCase().trim() : "";
  if (!Object.values(PROVIDER_VERDICTS).includes(verdict)) {
    return fallback;
  }

  const signals = Array.isArray(raw.signals)
    ? raw.signals
        .filter((s) => s && typeof s.code === "string" && s.code)
        .map((s) => ({ code: s.code, points: Number.isFinite(s.points) ? s.points : 0 }))
        .slice(0, 20)
    : [];

  return Object.freeze({
    verdict,
    source: typeof raw.source === "string" && raw.source ? raw.source : source,
    signals: Object.freeze(signals),
    detail: typeof raw.detail === "string" ? raw.detail : undefined,
    error: typeof raw.error === "string" ? raw.error : undefined,
  });
}

/**
 * The provider every implementation must satisfy.
 * @typedef {Object} ThreatProvider
 * @property {string} id - Stable provider identifier.
 * @property {boolean} available - Whether this provider can produce results.
 * @property {(ctx: object) => Promise<ProviderResult>} query - Lookup.
 */

/**
 * Provider that reports `unavailable` for everything.
 *
 * The default when threat intelligence is off. It makes the "no provider" case
 * explicit and testable rather than an implicit absence.
 *
 * @returns {ThreatProvider}
 */
export function createNullProvider() {
  return Object.freeze({
    id: "null",
    available: false,
    async query() {
      return normalizeProviderResult(
        { verdict: PROVIDER_VERDICTS.UNAVAILABLE, error: "no provider configured" },
        "null",
      );
    },
  });
}

/**
 * Provider that restates the local heuristic verdict.
 *
 * This is NOT threat intelligence — it performs no external lookup. It exists so
 * the engine has a uniform input shape today and a real adapter can be dropped
 * in later without touching the engine. It cannot change the final verdict,
 * because the engine ignores provider escalation for local-safe results.
 *
 * @param {{evaluate: Function}} deps - The local scoring function.
 * @returns {ThreatProvider}
 */
export function createLocalProvider(deps) {
  const evaluate = deps && typeof deps.evaluate === "function" ? deps.evaluate : null;
  return Object.freeze({
    id: "local",
    available: true,
    async query(ctx) {
      if (!evaluate) {
        return normalizeProviderResult(
          { verdict: PROVIDER_VERDICTS.UNAVAILABLE, error: "no local evaluator" },
          "local",
        );
      }
      try {
        const localVerdict = evaluate(ctx).verdict;
        const mapped =
          localVerdict === "dangerous"
            ? PROVIDER_VERDICTS.MALICIOUS
            : localVerdict === "suspicious"
              ? PROVIDER_VERDICTS.SUSPICIOUS
              : PROVIDER_VERDICTS.SAFE;
        return normalizeProviderResult({ verdict: mapped }, "local");
      } catch {
        return normalizeProviderResult(
          { verdict: PROVIDER_VERDICTS.UNAVAILABLE, error: "local evaluation failed" },
          "local",
        );
      }
    },
  });
}

/**
 * Picks the provider to use for a settings object.
 *
 * External intelligence stays off unless a real provider is registered, so
 * there is currently no configuration that can enable it.
 *
 * @param {Record<string, unknown>} settings - Current settings.
 * @param {Record<string, ThreatProvider>} [registry] - Available providers.
 * @returns {ThreatProvider} The provider to use.
 */
export function selectProvider(settings, registry) {
  const providers = registry && typeof registry === "object" ? registry : {};
  const enabled = settings && settings.threatIntel === true;
  if (enabled && providers.http && typeof providers.http.query === "function") {
    return providers.http;
  }
  return createNullProvider();
}
