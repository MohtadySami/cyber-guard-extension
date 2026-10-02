// Pure, DOM-free popup helpers for Cyber Guard.
// Kept separate from popup.js so the behaviour can be unit tested under
// `node --test` without a browser DOM. No chrome.* calls happen at module
// scope; chrome.runtime is only touched inside sendMessage().

/**
 * Sends exactly one message to the background service worker.
 *
 * Regression guard: an earlier version invoked chrome.runtime.sendMessage twice
 * per call (once without a callback purely to "check" for a promise, then again
 * with the callback). That executed every settings write and every history clear
 * twice. This helper performs a single call and reads runtime.lastError inside
 * the callback so Chrome does not log an unchecked-lastError warning.
 *
 * @param {Record<string, unknown>} msg - The message object.
 * @returns {Promise<{ok: boolean, error?: string}>} The background response, or a
 *   normalised error object. Never rejects.
 */
export function sendMessage(msg) {
  return new Promise((resolve) => {
    let runtime;
    try {
      runtime = typeof chrome !== "undefined" ? chrome.runtime : undefined;
    } catch (_error) {
      runtime = undefined;
    }

    if (!runtime || typeof runtime.sendMessage !== "function") {
      resolve({ ok: false, error: "runtime unavailable" });
      return;
    }

    let settled = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };

    try {
      runtime.sendMessage(msg, (response) => {
        // Must read lastError here; reading it later is a documented Chrome
        // requirement to suppress the "Unchecked runtime.lastError" warning.
        const lastError = runtime.lastError;
        if (lastError) {
          finish({ ok: false, error: lastError.message || String(lastError) });
          return;
        }
        if (!response || typeof response !== "object") {
          finish({ ok: false, error: "invalid response" });
          return;
        }
        finish(response);
      });
    } catch (error) {
      finish({ ok: false, error: error?.message || String(error) });
    }
  });
}

/**
 * Visual presentation for each verdict badge shown in the popup history list.
 * @type {Readonly<Record<string, {label: string, className: string}>>}
 */
export const VERDICT_PRESENTATION = Object.freeze({
  safe: Object.freeze({ label: "آمن", className: "verdict-safe" }),
  suspicious: Object.freeze({ label: "مشكوك", className: "verdict-suspicious" }),
  dangerous: Object.freeze({ label: "خطير", className: "verdict-dangerous" }),
});

/**
 * Maps a verdict string to its badge label and CSS class.
 *
 * @param {string} verdict - The verdict value.
 * @returns {{label: string, className: string}|null} Badge info, or null when the
 *   verdict is not one of the three known values.
 */
export function getVerdictPresentation(verdict) {
  if (typeof verdict !== "string") {
    return null;
  }
  return VERDICT_PRESENTATION[verdict] || null;
}

/**
 * Converts a stored history entry into the view model rendered by the popup.
 *
 * Reads the *normalised* history schema produced by lib/history.js, whose
 * canonical key is `hostname`. A legacy `host` key is still accepted so entries
 * written by earlier builds keep rendering. (Regression guard: the popup used to
 * read `entry.host` only, so the hostname column was silently always blank.)
 *
 * @param {Record<string, unknown>} entry - A stored decision-history entry.
 * @returns {{filename: string, meta: string, verdict: string}} View model.
 */
export function toHistoryRow(entry) {
  const item = entry && typeof entry === "object" ? entry : {};

  const filename = typeof item.filename === "string" ? item.filename : "";

  let hostname = "";
  if (typeof item.hostname === "string" && item.hostname) {
    hostname = item.hostname;
  } else if (typeof item.host === "string" && item.host) {
    hostname = item.host;
  }

  const parts = [];
  if (hostname) {
    parts.push(hostname);
  }
  if (typeof item.score === "number" && Number.isFinite(item.score)) {
    parts.push(`score:${item.score}`);
  }
  if (typeof item.timestamp === "number" && Number.isFinite(item.timestamp)) {
    const date = new Date(item.timestamp);
    if (!Number.isNaN(date.getTime())) {
      parts.push(date.toLocaleString());
    }
  }

  return {
    filename,
    meta: parts.join(" | "),
    verdict: typeof item.verdict === "string" ? item.verdict : "",
  };
}

/**
 * Builds the settings patch sent by the popup.
 *
 * Only UI-managed fields are included. Backend fields are deliberately absent:
 * backend analysis was removed from 0.1.0, so the popup must not write them.
 *
 * @param {{sensitivity?: string, enabled?: boolean}} form - Current form values.
 * @returns {Record<string, unknown>} The settings patch.
 */
export function buildSettingsPatch(form) {
  const source = form && typeof form === "object" ? form : {};
  const patch = {};

  if (source.sensitivity === "low" || source.sensitivity === "medium" || source.sensitivity === "high") {
    patch.sensitivity = source.sensitivity;
  }
  patch.enabled = source.enabled !== false;

  return patch;
}
