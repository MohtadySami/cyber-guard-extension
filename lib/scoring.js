// Scoring engine for converting heuristic reasons to verdicts.
// This module is pure and has no chrome.* usage.

import { runAllHeuristics, getHostname } from "./heuristics.js";

export const SCORING_CONSTANTS = Object.freeze({
  THRESHOLDS: Object.freeze({
    low: Object.freeze({ suspicious: 40, dangerous: 70 }),
    medium: Object.freeze({ suspicious: 30, dangerous: 60 }),
    high: Object.freeze({ suspicious: 20, dangerous: 50 }),
  }),
  HARD_SIGNAL_CODES: Object.freeze([
    "RTLO_CHARACTER",
    "DOUBLE_EXTENSION",
    "MIME_MISMATCH",
  ]),
  ENFORCE_VERDICTS: false,
});

function asSettings(settings) {
  return settings && typeof settings === "object" ? settings : {};
}

function normalizeSensitivity(sensitivity) {
  const valid = ["low", "medium", "high"];
  return typeof sensitivity === "string" && valid.includes(sensitivity)
    ? sensitivity
    : "medium";
}

function getSourceUrl(ctx) {
  const safeCtx = ctx && typeof ctx === "object" ? ctx : {};
  if (typeof safeCtx.finalUrl === "string" && safeCtx.finalUrl) {
    return safeCtx.finalUrl;
  }
  if (typeof safeCtx.url === "string" && safeCtx.url) {
    return safeCtx.url;
  }
  return "";
}

export function computeScore(reasons) {
  if (!Array.isArray(reasons)) {
    return 0;
  }
  let sum = 0;
  for (let i = 0; i < reasons.length; i++) {
    const r = reasons[i];
    if (r && typeof r.points === "number" && Number.isFinite(r.points) && r.points > 0) {
      sum += r.points;
    }
  }
  if (sum > 100) {
    sum = 100;
  }
  if (sum < 0) {
    sum = 0;
  }
  return Math.trunc(sum);
}

export function getVerdict(score, sensitivity) {
  const sens = normalizeSensitivity(sensitivity);
  const thresholds = SCORING_CONSTANTS.THRESHOLDS[sens];
  const s = typeof score === "number" && Number.isFinite(score) ? score : 0;
  if (s >= thresholds.dangerous) {
    return "dangerous";
  }
  if (s >= thresholds.suspicious) {
    return "suspicious";
  }
  return "safe";
}

export function isTrustedHost(host, trustedDomains) {
  if (typeof host !== "string" || !host) {
    return false;
  }
  const hostname = host.toLowerCase().trim();
  if (!hostname || hostname === "localhost") {
    return false;
  }
  if (!Array.isArray(trustedDomains)) {
    return false;
  }
  for (let i = 0; i < trustedDomains.length; i++) {
    const d = trustedDomains[i];
    if (typeof d !== "string" || !d) {
      continue;
    }
    const domain = d.toLowerCase().trim();
    if (!domain) {
      continue;
    }
    if (hostname === domain) {
      return true;
    }
    // Must end with dot + domain, never plain substring
    if (hostname.endsWith("." + domain)) {
      return true;
    }
  }
  return false;
}

export function topReasons(verdict, n = 3) {
  if (!verdict || !Array.isArray(verdict.reasons)) {
    return [];
  }
  const top = verdict.reasons
    .filter((r) => r && typeof r.points === "number" && r.points > 0)
    .sort((a, b) => {
      const pa = typeof a.points === "number" ? a.points : 0;
      const pb = typeof b.points === "number" ? b.points : 0;
      if (pb !== pa) {
        return pb - pa;
      }
      return 0;
    })
    .slice(0, n);
  return top;
}

export function evaluate(ctx, settings) {
  const safeCtx = ctx && typeof ctx === "object" ? ctx : {};
  const safeSettings = asSettings(settings);
  const sensitivity = normalizeSensitivity(safeSettings.sensitivity);
  const trustedDomains = Array.isArray(safeSettings.trustedDomains) ? safeSettings.trustedDomains : [];
  const sourceUrl = getSourceUrl(safeCtx);
  const sourceHost = getHostname(sourceUrl);

  let reasons = runAllHeuristics(safeCtx);
  // Sort by points desc
  reasons = reasons.slice().sort((a, b) => {
    const pa = typeof a.points === "number" ? a.points : 0;
    const pb = typeof b.points === "number" ? b.points : 0;
    if (pb !== pa) {
      return pb - pa;
    }
    return 0;
  });

  const hasHardSignal = reasons.some((r) => {
    return r && typeof r.code === "string" && SCORING_CONSTANTS.HARD_SIGNAL_CODES.includes(r.code);
  });

  const trusted = isTrustedHost(sourceHost, trustedDomains);
  if (trusted && !hasHardSignal) {
    // Score 0, verdict safe, reasons with one informational
    return {
      score: 0,
      verdict: "safe",
      reasons: [
        {
          code: "TRUSTED_DOMAIN",
          points: 0,
          text: `Source host ${sourceHost} is trusted`,
        },
      ],
      source: "local",
    };
  }

  // If trusted but hard signal present, score normally and keep reasons
  const score = computeScore(reasons);
  const verdict = getVerdict(score, sensitivity);

  return {
    score,
    verdict,
    reasons,
    source: "local",
  };
}
