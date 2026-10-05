import { evaluate } from "./lib/scoring.js";
import { buildNotificationTitle, buildNotificationMessage, buildCompletedNotificationTitle, buildCompletedNotificationMessage } from "./lib/alert.js";
import { getHostname, resolveFilename } from "./lib/heuristics.js";
import { getHistory, addHistoryEntry, clearHistory } from "./lib/history.js";
import {
  normalizeLanguage,
  getNotificationButtons,
  loadCatalogue,
  hasCatalogue,
} from "./lib/i18n.js";
import { assess, THREAT_STATES } from "./lib/threat/engine.js";
import { selectProvider } from "./lib/threat/provider.js";
import {
  shouldAlertOnPage,
  buildAlertPayload,
  renderPageAlert,
  hasPageAlertPermission,
  PAGE_ALERT_PERMISSION,
} from "./lib/page-alert.js";
// A. Constants

const DEFAULT_SETTINGS = {
  enabled: true,
  autoResumeSafe: true,
  trustedDomains: [],
  sensitivity: "medium",
  // UI language only. Presentation never affects analysis. Installations from
  // 0.1.x stored an explicit `language`, so they keep their choice; only installs
  // with no stored value get the 0.2.0 default.
  language: "en",
  // Page threat alerts are opt-in. `scripting` is an OPTIONAL permission, so
  // nothing is granted until the user explicitly enables this.
  pageAlerts: false,
  // No external threat-intelligence provider ships in 0.2.0.
  threatIntel: false,
};

// Backend analysis was never implemented and was removed for 0.1.0. These keys
// can still exist in chrome.storage.local from earlier builds, so they are
// stripped on every read/write instead of being silently carried forward.
const RETIRED_SETTINGS_KEYS = Object.freeze(["useBackend", "backendUrl"]);

/**
 * Removes retired settings keys from a settings object.
 *
 * @param {Record<string, unknown>} settings - Settings to clean.
 * @returns {Record<string, unknown>} A copy without retired keys.
 */
function stripRetiredSettings(settings) {
  const cleaned = { ...settings };
  for (const key of RETIRED_SETTINGS_KEYS) {
    delete cleaned[key];
  }
  return cleaned;
}

const DEBUG_ANALYSIS_DELAY_MS = 2000;
const DEBUG_FORCE_ERROR = false;
const DECISION_TIMEOUT_MS = 120000;
const LOG_PREFIX = "[DG]";

const activeResolutions = new Set();
// Guards against notifying twice about the same download when a state change and
// an analysis completion both land for it.
const completedRiskNotified = new Set();

// B. Storage helpers

/**
 * Returns the configured settings merged with safe defaults.
 *
 * @returns {Promise<Record<string, unknown>>} The current settings.
 */
async function getSettings() {
  try {
    const { settings = {} } = await chrome.storage.local.get("settings");
    const merged = {
      ...DEFAULT_SETTINGS,
      ...stripRetiredSettings(
        settings && typeof settings === "object" ? settings : {},
      ),
    };
    // A missing or malformed language must never leak through to the UI.
    merged.language = normalizeLanguage(merged.language);
    return merged;
  } catch (error) {
    console.error(`${LOG_PREFIX} settings read failed; using defaults`, error);
    return { ...DEFAULT_SETTINGS };
  }
}

/**
 * Merges and persists a partial settings update.
 *
 * @param {Record<string, unknown>} partial - Settings fields to update.
 * @returns {Promise<Record<string, unknown>>} The saved settings.
 */
async function setSettings(partial) {
  try {
    const current = await getSettings();
    const next = stripRetiredSettings({
      ...current,
      ...(partial && typeof partial === "object" ? partial : {}),
    });
    if (Object.hasOwn(next, "language")) {
      next.language = normalizeLanguage(next.language);
    }
    await chrome.storage.local.set({ settings: next });
    return next;
  } catch (error) {
    console.error(`${LOG_PREFIX} settings write failed`, error);
    return await getSettings();
  }
}

/**
 * Builds the isolated session-storage key for one download.
 *
 * @param {number} downloadId - Chrome's download identifier.
 * @returns {string} The storage key for the pending download.
 */
function pendingKey(downloadId) {
  return `pending:${downloadId}`;
}

/**
 * Stores pending state without a shared read-modify-write object.
 *
 * @param {number} downloadId - Chrome's download identifier.
 * @param {Record<string, unknown>} data - Minimal recovery context.
 * @returns {Promise<boolean>} Whether the pending entry was written.
 */
async function markPending(downloadId, data) {
  try {
    await chrome.storage.session.set({ [pendingKey(downloadId)]: data });
    return true;
  } catch (error) {
    console.error(`${LOG_PREFIX} pending write failed #${downloadId}`, error);
    return false;
  }
}

/**
 * Removes the session state for one download.
 *
 * @param {number} downloadId - Chrome's download identifier.
 * @returns {Promise<boolean>} Whether the pending entry was cleared.
 */
async function clearPending(downloadId) {
  try {
    await chrome.storage.session.remove(pendingKey(downloadId));
    return true;
  } catch (error) {
    console.error(`${LOG_PREFIX} pending clear failed #${downloadId}`, error);
    return false;
  }
}

/**
 * Reads every isolated pending-download entry from session storage.
 *
 * @returns {Promise<Array<{id: number, data: Record<string, unknown>}>>} Pending downloads.
 */
async function getAllPending() {
  try {
    const entries = await chrome.storage.session.get(null);
    return Object.entries(entries)
      .filter(([key]) => key.startsWith("pending:"))
      .map(([key, data]) => ({
        id: Number(key.slice("pending:".length)),
        data: data && typeof data === "object" ? data : {},
      }))
      .filter(({ id }) => Number.isInteger(id));
  } catch (error) {
    console.error(`${LOG_PREFIX} pending read failed`, error);
    return [];
  }
}

// C. Logging helper

/**
 * Emits a consistent, searchable service-worker lifecycle log.
 *
 * @param {string} step - The lifecycle step that completed.
 * @param {number|string} downloadId - Download identifier or a system label.
 * @param {string} [details=""] - Extra diagnostic information.
 */
function log(step, downloadId, details = "") {
  console.log(`${LOG_PREFIX} ${step} #${downloadId} ${details}`.trim());
}

// D. Download handling

/**
 * Resolves the originating tab ID for a download.
 *
 * Resolution strategy — strictly evidence-based, never a guess:
 *
 * 1. Use context.tabId if it is already a valid integer ≥ 0.
 * 2. If context.referrer is an HTTP/HTTPS URL, search open tabs by that URL.
 *    This only works if the optional host permission has been granted.
 *
 * There is NO active-tab fallback. Injecting a Cyber Guard alert into an
 * arbitrary active tab (which the user may have switched to after starting the
 * download) would display a misleading warning on an unrelated page. When no
 * source tab can be reliably identified, the caller falls back to the Chrome
 * notification, which is always correct.
 *
 * @param {Record<string, unknown>} context - Download item or alert context.
 * @returns {Promise<number|null>} Resolved tab ID, or null if not determinable.
 */
async function resolveOriginatingTabId(context) {
  if (context && Number.isInteger(context.tabId) && context.tabId >= 0) {
    return context.tabId;
  }
  if (typeof chrome === "undefined" || !chrome.tabs || typeof chrome.tabs.query !== "function") {
    return null;
  }
  if (context && typeof context.referrer === "string" && context.referrer.startsWith("http")) {
    try {
      const tabs = await chrome.tabs.query({ url: context.referrer });
      if (tabs && tabs.length > 0 && Number.isInteger(tabs[0].id) && tabs[0].id >= 0) {
        log("resolve tab by referrer", context?.id || "unknown", `tabId=${tabs[0].id}`);
        return tabs[0].id;
      }
    } catch (err) {
      log("resolve tab error", context?.id || "unknown", err?.message || String(err));
    }
  }
  // No reliable originating tab can be identified — caller uses notification fallback.
  return null;
}

/**
 * Pauses, performs the Step 1 analysis stub, then always attempts to resume a download.
 *
 * @param {chrome.downloads.DownloadItem} item - The newly created download.
 * @returns {Promise<void>}
 */
async function handleNewDownload(item) {
  const settings = await getSettings();
  const downloadId = item.id;

  if (!settings.enabled) {
    log("skipped (disabled)", downloadId, "download left untouched");
    return;
  }

  // Resolve originating tab early while user focus is still on the download page
  const originatingTabId = await resolveOriginatingTabId(item);
  if (originatingTabId !== null && item.tabId === undefined) {
    item.tabId = originatingTabId;
  }

  log("created", downloadId, item.filename || item.url || "unknown download");

  if (item.state !== "in_progress") {
    log("skipped (already finished)", downloadId, `state=${item.state}`);
    return;
  }

  let shouldSettle = false;
  let outcome = "pending";

  try {
    const pendingSaved = await markPending(downloadId, {
      url: item.url,
      filename: item.filename,
      tabId: item.tabId,
      startedAt: Date.now(),
    });
    log(
      "pending marked",
      downloadId,
      pendingSaved ? "session state saved" : "session state unavailable",
    );

    try {
      log("pause requested", downloadId);
      await chrome.downloads.pause(downloadId);
      shouldSettle = true;
      log("paused", downloadId);
    } catch (pauseError) {
      log("pause failed", downloadId, pauseError?.message || String(pauseError));

      let latestItem;
      try {
        [latestItem] = await chrome.downloads.search({ id: downloadId });
      } catch (searchError) {
        log("pause re-query failed", downloadId, searchError?.message || String(searchError));
      }

      if (!latestItem || latestItem.state !== "in_progress") {
        log("too late to pause", downloadId, `state=${latestItem?.state || "not found"}`);
        return;
      }

      shouldSettle = true;
      log("analysis continuing", downloadId, "download remained in progress");
    }

    try {
      log("analysis started", downloadId, "local heuristics");
      const result = await analyzeDownload(item, settings);
      log("analysis finished", downloadId, `verdict=${result.verdict}, source=${result.source}`);

      let latestItem;
      try {
        [latestItem] = await chrome.downloads.search({ id: downloadId });
      } catch (searchError) {
        log("post-analysis search failed", downloadId, searchError?.message || String(searchError));
      }

      const isRisk =
        result && (result.verdict === "suspicious" || result.verdict === "dangerous");

      if (!latestItem || latestItem.state !== "in_progress") {
        // The download reached a terminal state while we were analysing it.
        //
        // A *completed* download can no longer be paused, but the verdict is
        // still actionable: the bytes are already on disk and
        // chrome.downloads.removeFile() can delete them. Previously this branch
        // discarded a risky verdict, which silently left a dangerous file
        // behind with no warning.
        //
        // Cancelled, interrupted and missing downloads stay un-actioned: there
        // is no completed file to warn about or remove.
        if (latestItem && latestItem.state === "complete" && isRisk) {
          log(
            "download completed before analysis finished",
            downloadId,
            `verdict=${result.verdict}, actioning completed file`,
          );
          if (item.tabId !== undefined) {
            latestItem.tabId = item.tabId;
          }
          outcome = await notifyCompletedRisk(latestItem, result);
        } else {
          log(
            "analysis result ignored",
            downloadId,
            `state=${latestItem?.state || "not found"}`,
          );
          outcome = "ignored";
        }
        return;
      }

      if (isRisk) {
        outcome = await holdDownload(item, result);
      } else {
        outcome = "resumed";
        const ctx = buildContext(item);
        const filename = resolveFilename(ctx);
        void maybeShowPageAlert({
          verdict: "safe",
          tabId: item.tabId,
          filename,
          reasons: result?.reasons || [],
          language: settings.language,
        }).catch(() => {});
      }
    } catch (analysisError) {
      log("analysis error", downloadId, analysisError?.message || String(analysisError));
      const result = { verdict: "safe", source: "error-fallback" };
      log("analysis fallback", downloadId, `verdict=${result.verdict}, source=${result.source}`);
      outcome = "resumed";
    }
  } catch (error) {
    log("handler error", downloadId, error?.message || String(error));
    outcome = "resumed";
  } finally {
    try {
      if (outcome === "pending") {
        log("safety net resume", downloadId, "outcome was pending");
        outcome = "resumed";
      }
      if (outcome === "resumed" && shouldSettle) {
        try {
          log("resume requested", downloadId);
          await chrome.downloads.resume(downloadId);
          log("resumed", downloadId);
        } catch (resumeError) {
          log("resume failed", downloadId, resumeError?.message || String(resumeError));
        }
      }

      // "held" and "notified" both leave a live pending record that
      // resolveDecision() still needs in order to act on the user's choice.
      if (outcome !== "held" && outcome !== "notified") {
        const pendingCleared = await clearPending(downloadId);
        log(
          "pending cleared",
          downloadId,
          pendingCleared ? "session state removed" : "session state cleanup failed",
        );
      }
    } catch (cleanupError) {
      log("finally cleanup error", downloadId, cleanupError?.message || String(cleanupError));
    }
  }
}

/**
 * Holds a risky download: saves verdict, creates notification, sets alarm.
 * Never throws. Returns the outcome: "held", "resumed", or "cancelled".
 * @param {chrome.downloads.DownloadItem} item
 * @param {{verdict: string, reasons: Array<any>, score?: number, source?: string}} result
 * @returns {Promise<string>}
 */
async function holdDownload(item, result) {
  const downloadId = item.id;
  const verdict = result?.verdict || "suspicious";
  try {
    const key = pendingKey(downloadId);
    let existing = {};
    try {
      const data = await chrome.storage.session.get(key);
      if (data && data[key]) {
        existing = data[key] || {};
      }
    } catch (_e) {
      // ignore
    }

    const sourceUrl = item.finalUrl || item.url || "";
    const host = getHostname(sourceUrl);
    const ctx = buildContext(item);
    const filename = resolveFilename(ctx);

    existing.verdict = verdict;
    existing.reasons = result?.reasons;
    existing.score = result?.score;
    existing.source = result?.source || "local";
    existing.filename = filename;
    existing.url = sourceUrl;
    existing.host = host;
    await chrome.storage.session.set({ [key]: existing });

    const language = normalizeLanguage((await getSettings()).language);
    await ensureCatalogue(language);

    log("notification creating", downloadId);
    let notificationFailed = false;
    let notificationErrorMsg = null;
    try {
      await new Promise((resolve) => {
        try {
          chrome.notifications.create(
            notificationIdForDownload(downloadId),
            {
              type: "basic",
              iconUrl: "icons/icon-128.png",
              title: buildNotificationTitle(verdict, language),
              message: buildNotificationMessage(filename, host, result?.reasons || [], language),
              requireInteraction: true,
              // Button order is the decision contract: 0 = cancel, 1 = allow.
              buttons: getNotificationButtons("held", language).map((title) => ({ title })),
            },
            (id) => {
              if (chrome.runtime.lastError) {
                resolve({ error: chrome.runtime.lastError.message });
              } else {
                resolve({ ok: true, id });
              }
            }
          );
        } catch (e) {
          console.error("[DG] notification construction/create exception", e);
          resolve({ error: e?.stack || e?.message || String(e) });
        }
      }).then((res) => {
        if (res && res.error) {
          notificationFailed = true;
          notificationErrorMsg = res.error;
        }
      });
    } catch (e) {
      notificationFailed = true;
      notificationErrorMsg = e?.message || String(e);
    }

    if (notificationFailed) {
      log("notification create failed", downloadId, notificationErrorMsg || "unknown error");
    } else {
      log("notification created", downloadId);
    }

    // Page alert is best-effort presentation; it never gates the decision.
    void maybeShowPageAlert({
      verdict,
      tabId: item.tabId,
      filename,
      reasons: result?.reasons || [],
      language,
    }).catch(() => {});

    const alarmDelayMs = DECISION_TIMEOUT_MS;
    try {
      await chrome.alarms.create(alarmNameForDownload(downloadId), {
        delayInMinutes: alarmDelayMs / 60000,
      });
      log("alarm set", downloadId, `dg-timeout-${downloadId} in ${alarmDelayMs}ms`);
    } catch (alarmErr) {
      log("alarm create failed", downloadId, alarmErr?.message || String(alarmErr));
    }

    if (notificationFailed) {
      if (verdict === "dangerous") {
        await resolveDecision(downloadId, "cancel", "notification-failed");
        return "cancelled";
      }
      await resolveDecision(downloadId, "allow", "notification-failed");
      return "resumed";
    }
    return "held";
  } catch (e) {
    log("holdDownload error", downloadId, e?.message || String(e));
    try {
      if (verdict === "dangerous") {
        await resolveDecision(downloadId, "cancel", "hold-error");
        return "cancelled";
      }
      await resolveDecision(downloadId, "allow", "hold-error");
      return "resumed";
    } catch (e2) {
      log("holdDownload fallback failed", downloadId, e2?.message || String(e2));
      return "resumed";
    }
  }
}

/**
 * Acts on a risky verdict for a download that finished before analysis could
 * pause it.
 *
 * The download is already complete, so it cannot be paused or cancelled, but the
 * file is on disk and chrome.downloads.removeFile() can still delete it. This
 * writes a pending record (so resolveDecision() can act), raises a persistent
 * notification offering "Delete file" / "Keep file", and applies the same
 * fail-safe alarm as a held download.
 *
 * Never throws. Returns "notified", "already-notified", "cancelled" or "resumed".
 *
 * @param {chrome.downloads.DownloadItem} item - The completed download.
 * @param {{verdict: string, reasons: Array<any>, score?: number, source?: string}} result - The verdict.
 * @returns {Promise<string>} The outcome.
 */
async function notifyCompletedRisk(item, result) {
  const downloadId = item.id;
  const verdict = result?.verdict === "dangerous" ? "dangerous" : "suspicious";

  // Requirement: never raise the same notification twice, however many state
  // changes or analysis completions land for this download.
  if (completedRiskNotified.has(downloadId)) {
    log("completed risk already notified", downloadId, `verdict=${verdict}`);
    return "already-notified";
  }
  completedRiskNotified.add(downloadId);

  try {
    const sourceUrl = item.finalUrl || item.url || "";
    const host = getHostname(sourceUrl);
    const ctx = buildContext(item);
    const filename = resolveFilename(ctx);

    // completedRisk marks the record so onDownloadsChanged() does not tear the
    // notification down when a later state delta arrives.
    await chrome.storage.session.set({
      [pendingKey(downloadId)]: {
        url: sourceUrl,
        filename,
        host,
        verdict,
        reasons: result?.reasons,
        score: result?.score,
        source: result?.source || "local",
        startedAt: Date.now(),
        completedAt: Date.now(),
        completedRisk: true,
      },
    });

    const language = normalizeLanguage((await getSettings()).language);
    await ensureCatalogue(language);

    // The file is already on disk, so this is the most important moment to warn
    // the user on the page itself.
    void maybeShowPageAlert({
      verdict,
      tabId: item.tabId,
      filename,
      reasons: result?.reasons || [],
      language,
    }).catch(() => {});

    log("completed notification creating", downloadId, `verdict=${verdict}`);
    let notificationFailed = false;
    let notificationErrorMsg = null;
    try {
      await new Promise((resolve) => {
        try {
          chrome.notifications.create(
            notificationIdForDownload(downloadId),
            {
              type: "basic",
              iconUrl: "icons/icon-128.png",
              title: buildCompletedNotificationTitle(verdict, language),
              message: buildCompletedNotificationMessage(
                filename,
                host,
                result?.reasons || [],
                language,
              ),
              requireInteraction: true,
              // Button order is the decision contract: 0 = delete, 1 = keep.
              buttons: getNotificationButtons("completed", language).map((title) => ({ title })),
            },
            (id) => {
              if (chrome.runtime.lastError) {
                resolve({ error: chrome.runtime.lastError.message });
              } else {
                resolve({ ok: true, id });
              }
            },
          );
        } catch (e) {
          console.error("[DG] completed notification construction/create exception", e);
          resolve({ error: e?.stack || e?.message || String(e) });
        }
      }).then((res) => {
        if (res && res.error) {
          notificationFailed = true;
          notificationErrorMsg = res.error;
        }
      });
    } catch (e) {
      notificationFailed = true;
      notificationErrorMsg = e?.message || String(e);
    }

    if (notificationFailed) {
      log("completed notification failed", downloadId, notificationErrorMsg || "unknown error");
    } else {
      log("completed notification created", downloadId, `verdict=${verdict}`);
    }

    try {
      await chrome.alarms.create(alarmNameForDownload(downloadId), {
        delayInMinutes: DECISION_TIMEOUT_MS / 60000,
      });
      log("alarm set", downloadId, `dg-timeout-${downloadId} in ${DECISION_TIMEOUT_MS}ms`);
    } catch (alarmErr) {
      log("alarm create failed", downloadId, alarmErr?.message || String(alarmErr));
    }

    if (notificationFailed) {
      // Fail safe without ever having asked the user: remove a dangerous file,
      // but keep a merely suspicious one rather than deleting silently.
      if (verdict === "dangerous") {
        await resolveDecision(downloadId, "cancel", "notification-failed");
        return "cancelled";
      }
      await resolveDecision(downloadId, "allow", "notification-failed");
      return "resumed";
    }
    return "notified";
  } catch (e) {
    log("notifyCompletedRisk error", downloadId, e?.message || String(e));
    try {
      if (verdict === "dangerous") {
        await resolveDecision(downloadId, "cancel", "hold-error");
        return "cancelled";
      }
      await resolveDecision(downloadId, "allow", "hold-error");
      return "resumed";
    } catch (e2) {
      log("notifyCompletedRisk fallback failed", downloadId, e2?.message || String(e2));
      return "resumed";
    }
  }
}

/**
 * Loads the message catalogue for a language, once per service-worker lifetime.
 *
 * The service worker must render notifications and inject page alerts in the
 * user's chosen language. `chrome.i18n` cannot be used for that (it resolves
 * against the browser locale, crbug/660704), so the catalogue is read directly
 * from the packaged _locales directory.
 *
 * @param {string} language - Normalized language code.
 * @returns {Promise<void>} Resolves once the catalogue is available or failed.
 */
async function ensureCatalogue(language) {
  const lang = normalizeLanguage(language);
  if (hasCatalogue(lang)) {
    return;
  }
  await loadCatalogue(lang, async (path) => {
    const response = await fetch(chrome.runtime.getURL(path));
    if (!response.ok) {
      throw new Error(`catalogue ${path} -> ${response.status}`);
    }
    return await response.json();
  });
}

/**
 * Shows the page threat alert in the tab a dangerous download came from.
 *
 * Injected one-shot via chrome.scripting.executeScript(); there is no
 * permanently registered content script. Does nothing unless the user granted
 * the optional `scripting` permission and enabled page alerts.
 *
 * Never throws and never affects the download decision.
 *
 * @param {{verdict: string, tabId?: number, filename?: string, reasons?: Array, language?: string}} params
 * @returns {Promise<boolean>} True when the alert was injected.
 */
async function maybeShowPageAlert(params) {
  const safe = params && typeof params === "object" ? params : {};
  const settings = await getSettings();
  if (settings.pageAlerts !== true) {
    return false;
  }

  let tabId = safe.tabId;
  if (!Number.isInteger(tabId) || tabId < 0) {
    tabId = await resolveOriginatingTabId(safe);
  }

  const safeWithTab = { ...safe, tabId };
  if (!shouldAlertOnPage(safeWithTab)) {
    log("page alert skipped", tabId, "shouldAlertOnPage returned false");
    return false;
  }

  const permissionsApi =
    typeof chrome !== "undefined" && chrome.permissions ? chrome.permissions : null;
  if (!(await hasPageAlertPermission(permissionsApi))) {
    log("page alert skipped", tabId, "permission not granted");
    return false;
  }
  if (
    typeof chrome === "undefined" ||
    !chrome.scripting ||
    typeof chrome.scripting.executeScript !== "function"
  ) {
    log("page alert skipped", tabId, "chrome.scripting unavailable");
    return false;
  }

  const language = normalizeLanguage(safe.language || settings.language);
  await ensureCatalogue(language);
  const reason = Array.isArray(safe.reasons) && safe.reasons.length > 0 ? safe.reasons[0] : null;
  const payload = buildAlertPayload({
    verdict: safe.verdict,
    filename: safe.filename,
    reason,
    language,
  });

  try {
    // `func` is serialized and run in the page's ISOLATED world, so it cannot
    // touch extension APIs and the page cannot reach its scope.
    await chrome.scripting.executeScript({
      target: { tabId },
      world: "ISOLATED",
      func: renderPageAlert,
      args: [payload],
    });
    log("page alert shown", tabId, `verdict=${safe.verdict} lang=${language}`);
    return true;
  } catch (error) {
    // A tab can be gone, chrome://, or the Web Store. Never fatal.
    log("page alert failed", tabId, error?.message || String(error));
    return false;
  }
}

/**
 * Builds a minimal context object from the DownloadItem.
 *
 * @param {chrome.downloads.DownloadItem} item - The download being analyzed.
 * @returns {{url: string, finalUrl: string, referrer: string, filename: string, mime: string, redirectChain: Array<string>, pageUrl: string}}
 */
function buildContext(item) {
  const safeItem = item && typeof item === "object" ? item : {};
  return {
    url: typeof safeItem.url === "string" ? safeItem.url : "",
    finalUrl: typeof safeItem.finalUrl === "string" ? safeItem.finalUrl : "",
    referrer: typeof safeItem.referrer === "string" ? safeItem.referrer : "",
    filename: typeof safeItem.filename === "string" ? safeItem.filename : "",
    mime: typeof safeItem.mime === "string" ? safeItem.mime : "",
    redirectChain: [],
    pageUrl: typeof safeItem.referrer === "string" ? safeItem.referrer : "",
  };
}

/**
 * Runs the local heuristic + scoring analysis for one download.
 *
 * Analysis is entirely local: no network request is made and no backend URL is
 * consulted. The configured delay keeps the download paused long enough for the
 * heuristics to run, matching the "pauses downloads briefly" product behaviour.
 *
 * @param {chrome.downloads.DownloadItem} item - The download being analyzed.
 * @param {Record<string, unknown>} settings - Current extension settings.
 * @returns {Promise<{score: number, verdict: string, reasons: Array, source: string}>} Analysis result.
 */
async function analyzeDownload(item, settings) {
  const ctx = buildContext(item);
  log("analysis delay", item.id, `${DEBUG_ANALYSIS_DELAY_MS}ms`);
  await new Promise((resolve) => setTimeout(resolve, DEBUG_ANALYSIS_DELAY_MS));

  if (DEBUG_FORCE_ERROR) {
    throw new Error("DEBUG_FORCE_ERROR is enabled");
  }

  let heuristicReasons;
  try {
    const firstPass = evaluate(ctx, { sensitivity: "medium" });
    heuristicReasons = firstPass.reasons;
  } catch (heuristicError) {
    log("heuristics error", item.id, heuristicError?.message || String(heuristicError));
    heuristicReasons = [];
  }

  for (let index = 0; index < heuristicReasons.length; index++) {
    const reason = heuristicReasons[index];
    const points = typeof reason.points === "number" ? reason.points : 0;
    log(
      `heuristic #${index + 1}`,
      item.id,
      `${reason.code} +${points} ${reason.text}`,
    );
  }

  let verdictResult;
  try {
    verdictResult = evaluate(ctx, settings);
  } catch (scoringError) {
    log("scoring error", item.id, scoringError?.message || String(scoringError));
    const scoreSum = heuristicReasons.reduce(
      (sum, reason) => (typeof reason.points === "number" ? sum + reason.points : sum),
      0,
    );
    verdictResult = {
      score: scoreSum,
      verdict: "safe",
      reasons: heuristicReasons,
      source: "error-fallback",
    };
  }

  log(
    "verdict",
    item.id,
    `${verdictResult.verdict} score=${verdictResult.score}`,
  );

  if (
    (verdictResult.verdict === "suspicious" || verdictResult.verdict === "dangerous")
  ) {
    log("holding", item.id, `(${verdictResult.verdict}) score=${verdictResult.score}`);
  }

  // Threat assessment is ADDITIVE. The verdict above is already final and is
  // never modified by this layer: the engine derives its state from the same
  // local verdict, and a provider can only corroborate it.
  let threat = null;
  try {
    threat = await assess(ctx, settings, {
      evaluate,
      provider: selectProvider(settings),
    });
    log(
      "threat state",
      item.id,
      `${threat.state} verdict=${threat.finalVerdict} provider=${threat.provider.verdict}`,
    );
  } catch (threatError) {
    log("threat engine error", item.id, threatError?.message || String(threatError));
  }

  return {
    downloadId: item.id,
    score: verdictResult.score,
    verdict: verdictResult.verdict,
    reasons: verdictResult.reasons,
    source: verdictResult.source,
    threat,
    timestamp: Date.now(),
  };
}

// E. Recovery on worker restart

/**
 * Resumes active paused downloads left behind by a service-worker restart.
 *
 * @param {string} trigger - The lifecycle event that triggered recovery.
 * @returns {Promise<void>}
 */
async function recoverPendingDownloads(trigger) {
  log("recovery started", "system", trigger);
  const pendingDownloads = await getAllPending();

  for (const { id: downloadId, data } of pendingDownloads) {
    // A held download, or a completed download already flagged to the user, has
    // a verdict stored in its session entry. The notification and alarm were
    // created before the restart and are still live. Leave the session entry
    // intact so resolveDecision() can still act on button/timeout.
    if (data && typeof data.verdict === "string" && data.verdict) {
      log(
        "recovery skipped (awaiting decision)",
        downloadId,
        `verdict=${data.verdict}${data.completedRisk ? ", completed" : ""}`,
      );
      continue;
    }

    // Non-held download: resume if still paused, then clear session state.
    let item;
    try {
      [item] = await chrome.downloads.search({ id: downloadId });
    } catch (searchError) {
      log("recovery search failed", downloadId, searchError?.message || String(searchError));
    }

    if (item?.state === "in_progress" && item.paused) {
      try {
        log("recovery resume requested", downloadId, trigger);
        await chrome.downloads.resume(downloadId);
        log("recovery resumed", downloadId);
      } catch (resumeError) {
        log("recovery resume failed", downloadId, resumeError?.message || String(resumeError));
      }
    } else {
      log("recovery skipped", downloadId, `state=${item?.state || "not found"}`);
    }

    const pendingCleared = await clearPending(downloadId);
    log(
      "recovery cleared",
      downloadId,
      pendingCleared ? "session state removed" : "session state cleanup failed",
    );
  }

  log("recovery finished", "system", `${pendingDownloads.length} pending download(s)`);
}


/**
 * Starts recovery after the extension is installed or updated.
 *
 * @param {chrome.runtime.InstalledDetails} details - Installation metadata.
 */
function onInstalled(details) {
  log("installed", "system", `reason=${details.reason}`);
  void recoverPendingDownloads("onInstalled");
}

/**
 * Starts recovery when Chrome begins a new browser session.
 */
function onStartup() {
  log("startup", "system");
  void recoverPendingDownloads("onStartup");
}

function onAlarm(alarm) {
  if (!alarm || !alarm.name || !alarm.name.startsWith("dg-timeout-")) {
    return;
  }
  const downloadId = Number(alarm.name.slice("dg-timeout-".length));
  if (!Number.isInteger(downloadId)) {
    return;
  }
  void resolveDecision(downloadId, "cancel", "timeout");
}

function onNotificationButtonClicked(notificationId, buttonIndex) {
  if (!notificationId || !notificationId.startsWith("dg-")) {
    return;
  }
  const downloadId = Number(notificationId.slice("dg-".length));
  if (!Number.isInteger(downloadId)) {
    return;
  }
  if (buttonIndex === 0) {
    void resolveDecision(downloadId, "cancel", "user-button");
  } else if (buttonIndex === 1) {
    void resolveDecision(downloadId, "allow", "user-button");
  }
}

function onNotificationClosed(notificationId, byUser) {
  if (!notificationId || !notificationId.startsWith("dg-")) {
    return;
  }
  const downloadId = Number(notificationId.slice("dg-".length));
  if (!Number.isInteger(downloadId)) {
    return;
  }
  if (byUser) {
    void resolveDecision(downloadId, "cancel", "notification-closed");
  }
}

async function onDownloadsChanged(downloadDelta) {
  const downloadId = downloadDelta.id;
  if (!Number.isInteger(downloadId)) {
    return;
  }
  const key = pendingKey(downloadId);
  let pending = null;
  try {
    const data = await chrome.storage.session.get(key);
    pending = data && data[key] ? data[key] : null;
  } catch (_e) {
    // ignore
  }
  if (!pending) {
    return;
  }

  // A completed download we already flagged is awaiting the user's answer on a
  // notification and alarm that are still live. A repeated state delta must not
  // tear them down, and must not record a duplicate decision.
  if (pending.completedRisk === true) {
    log(
      "external state change ignored (awaiting decision)",
      downloadId,
      `state=${downloadDelta.state?.current || "n/a"}`,
    );
    return;
  }

  if (downloadDelta.state && downloadDelta.state.current !== "in_progress") {
    // Download ended externally (e.g., user cancelled via Chrome download bar).
    // Clean up the associated UI and session state. resolveDecision() is not
    // called here because the download is already terminal.
    log("external state change", downloadId, `state=${downloadDelta.state.current}`);
    await clearNotificationForDownload(downloadId);
    await clearAlarmForDownload(downloadId);
    await clearPending(downloadId);
    log("external cleanup done", downloadId);
  }
}

function alarmNameForDownload(downloadId) {
  return `dg-timeout-${downloadId}`;
}

function notificationIdForDownload(downloadId) {
  return `dg-${downloadId}`;
}

async function clearAlarmForDownload(downloadId) {
  try {
    await chrome.alarms.clear(alarmNameForDownload(downloadId));
  } catch (error) {
    log("alarm clear failed", downloadId, error?.message || String(error));
  }
}

async function clearNotificationForDownload(downloadId) {
  try {
    chrome.notifications.clear(notificationIdForDownload(downloadId), () => {});
  } catch (error) {
    log("notification clear failed", downloadId, error?.message || String(error));
  }
}

/**
 * Resolves a held download decision.
 *
 * @param {number} downloadId - Download ID.
 * @param {"allow" | "cancel"} action - User action.
 * @param {string} cause - Cause of decision.
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
async function resolveDecision(downloadId, action, cause) {
  if (activeResolutions.has(downloadId)) {
    return { ok: false, error: "already resolved" };
  }
  activeResolutions.add(downloadId);

  try {
    const key = pendingKey(downloadId);
    let pending;
    try {
      const data = await chrome.storage.session.get(key);
      pending = data[key];
      if (!pending || typeof pending !== "object") {
        activeResolutions.delete(downloadId);
        return { ok: false, error: "already resolved" };
      }
    } catch (error) {
      log("resolve read pending failed", downloadId, error?.message || String(error));
      activeResolutions.delete(downloadId);
      return { ok: false, error: error?.message || String(error) };
    }

    if (action === "allow") {
      let allowSucceeded = false;
      let allowError = null;
      try {
        await chrome.downloads.resume(downloadId);
        allowSucceeded = true;
      } catch (resumeError) {
        allowError = resumeError;
        // A download that already completed cannot be resumed. For "allow" that
        // is the desired end state (keep the finished file), not a failure, so
        // confirm the download is terminal and carry on to record the decision.
        let item;
        try {
          [item] = await chrome.downloads.search({ id: downloadId });
        } catch (_sErr) {
          // ignore
        }
        if (item && item.state !== "in_progress") {
          allowSucceeded = true;
          log("decision allow (already finished)", downloadId, `state=${item.state}`);
        }
      }
      if (!allowSucceeded) {
        log(
          "decision allow resume failed",
          downloadId,
          allowError?.message || String(allowError),
        );
        activeResolutions.delete(downloadId);
        return { ok: false, error: allowError?.message || String(allowError) };
      }
      log("decision allow", downloadId, cause);
    } else if (action === "cancel") {
      let cancelSuccess = false;
      try {
        await chrome.downloads.cancel(downloadId);
        cancelSuccess = true;
      } catch (cancelError) {
        let item;
        try {
          [item] = await chrome.downloads.search({ id: downloadId });
        } catch (_sErr) {
          // ignore
        }
        if (item && item.state !== "in_progress") {
          cancelSuccess = true;
        } else {
          log("decision cancel failed", downloadId, cancelError?.message || String(cancelError));
          activeResolutions.delete(downloadId);
          return { ok: false, error: cancelError?.message || String(cancelError) };
        }
      }

      if (cancelSuccess) {
        try {
          await chrome.downloads.removeFile(downloadId);
        } catch (e) {
          log("decision removeFile failed", downloadId, e?.message || String(e));
        }
        try {
          await chrome.downloads.erase({ id: downloadId });
        } catch (e) {
          log("decision erase failed", downloadId, e?.message || String(e));
        }
        log("decision cancel", downloadId, cause);
      }
    }

    // Chrome operation succeeded or verified terminal.
    // 1. Record persistent history entry BEFORE clearing pending session state
    try {
      await addHistoryEntry({
        downloadId: downloadId,
        timestamp: Date.now(),
        filename: pending.filename || "",
        url: pending.url || "",
        hostname: pending.host || pending.hostname || "",
        verdict: pending.verdict || "unknown",
        score: typeof pending.score === "number" ? pending.score : 0,
        decision: action,
        cause: cause,
        source: pending.source || "local",
      });
    } catch (historyErr) {
      log("history record error", downloadId, historyErr?.message || String(historyErr));
    }

    // 2. Clean up notification, alarm, and pending session storage.
    await clearNotificationForDownload(downloadId);
    await clearAlarmForDownload(downloadId);
    await clearPending(downloadId);

    return { ok: true };
  } catch (error) {
    log("resolve decision error", downloadId, error?.message || String(error));
    activeResolutions.delete(downloadId);
    return { ok: false, error: error?.message || String(error) };
  }
}

// F. Message handlers (stubs only)

/**
 * Reports the current visual threat state for the popup.
 *
 * Derived from the most recent risky decision in history, so it survives a
 * service-worker restart. Defaults to SECURE.
 *
 * @returns {Promise<{state: string, verdict: string, score: number}>} The state.
 */
async function getThreatState() {
  const settings = await getSettings();
  if (settings.enabled === false) {
    return { state: THREAT_STATES.SECURE, verdict: "safe", score: 0 };
  }
  let history = [];
  try {
    history = await getHistory();
  } catch {
    history = [];
  }
  const latest = Array.isArray(history) && history.length > 0 ? history[0] : null;
  const verdict = latest && typeof latest.verdict === "string" ? latest.verdict : "safe";
  const score = latest && Number.isFinite(latest.score) ? latest.score : 0;
  return {
    state: verdict === "dangerous" ? THREAT_STATES.THREAT : THREAT_STATES.SECURE,
    verdict,
    score,
  };
}

/**
 * Requests the optional `scripting` permission for page threat alerts.
 *
 * Requires a user gesture, so it is only ever called from the popup. A denial is
 * a normal outcome, not an error: the feature stays off.
 *
 * @returns {Promise<boolean>} True when the permission was granted.
 */
async function requestPageAlertPermission() {
  const permissionsApi =
    typeof chrome !== "undefined" && chrome.permissions ? chrome.permissions : null;
  if (!permissionsApi) {
    return false;
  }
  if (await hasPageAlertPermission(permissionsApi)) {
    await setSettings({ pageAlerts: true });
    return true;
  }
  if (typeof permissionsApi.request !== "function") {
    return false;
  }
  try {
    const granted = await permissionsApi.request(PAGE_ALERT_PERMISSION);
    if (granted === true) {
      await setSettings({ pageAlerts: true });
      return true;
    }
    // Explicitly record the refusal so the popup can explain itself.
    await setSettings({ pageAlerts: false });
    return false;
  } catch (error) {
    log("page alert permission error", "system", error?.message || String(error));
    await setSettings({ pageAlerts: false });
    return false;
  }
}

/**
 * Responds to the Step 1 settings messages and reserves the remaining UI contract.
 *
 * @param {Record<string, unknown>} message - The incoming runtime message.
 * @param {chrome.runtime.MessageSender} sender - The message sender.
 * @param {(response?: unknown) => void} sendResponse - Async response callback.
 * @returns {boolean|undefined} True only when the response is asynchronous.
 */
function onMessage(message, sender, sendResponse) {
  if (!message || typeof message.type !== "string") {
    return undefined;
  }
  if (sender && sender.id && sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false, error: "rejected" });
    return undefined;
  }

  if (message.type === "GET_THREAT_STATE") {
    void getThreatState()
      .then((state) => sendResponse({ ok: true, state }))
      .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));
    return true;
  }

  if (message.type === "REQUEST_PAGE_ALERT_PERMISSION") {
    void requestPageAlertPermission()
      .then((granted) => sendResponse({ ok: true, granted }))
      .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));
    return true;
  }

  if (message.type === "GET_SETTINGS") {
    void getSettings()
      .then((settings) => sendResponse({ ok: true, settings }))
      .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));
    return true;
  }

  if (message.type === "SET_SETTINGS") {
    void setSettings(message.settings)
      .then((settings) => sendResponse({ ok: true, settings }))
      .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));
    return true;
  }

  if (message.type === "USER_DECISION") {
    const downloadId = message.downloadId;
    const action = message.action;
    if (typeof downloadId !== "number" || !Number.isInteger(downloadId)) {
      sendResponse({ ok: false, error: "invalid downloadId" });
      return undefined;
    }
    if (action !== "allow" && action !== "cancel") {
      sendResponse({ ok: false, error: "invalid action" });
      return undefined;
    }
    void resolveDecision(downloadId, action, "message")
      .then((res) => sendResponse(res))
      .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));
    return true;
  }

  if (message.type === "GET_HISTORY") {
    void getHistory()
      .then((history) => sendResponse({ ok: true, history }))
      .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));
    return true;
  }

  if (message.type === "CLEAR_HISTORY") {
    void clearHistory()
      .then((ok) => sendResponse({ ok }))
      .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));
    return true;
  }

  if (["ANALYZE_URL"].includes(message.type)) {
    sendResponse({ ok: false, error: "not implemented" });
    return undefined;
  }

  return undefined;
}

// TODO(step 3): redirect tracking + typosquat detection. Still outstanding:
// buildContext() hardcodes redirectChain: [], so the redirect-chain and
// lookalike-domain heuristics currently always see an empty chain.

// G. Listener registration (must remain synchronous and top-level)

chrome.downloads.onCreated.addListener(handleNewDownload);
chrome.runtime.onMessage.addListener(onMessage);
chrome.runtime.onInstalled.addListener(onInstalled);
chrome.runtime.onStartup.addListener(onStartup);
chrome.alarms.onAlarm.addListener(onAlarm);
chrome.notifications.onButtonClicked.addListener(onNotificationButtonClicked);
chrome.notifications.onClosed.addListener(onNotificationClosed);
chrome.downloads.onChanged.addListener(onDownloadsChanged);

void recoverPendingDownloads("worker startup");

export {
  handleNewDownload,
  holdDownload,
  notifyCompletedRisk,
  completedRiskNotified,
  resolveDecision,
  activeResolutions,
  recoverPendingDownloads,
  onDownloadsChanged,
  markPending,
  clearPending,
  pendingKey,
  getSettings,
  setSettings,
  getHistory,
  addHistoryEntry,
  clearHistory,
  getThreatState,
  requestPageAlertPermission,
  maybeShowPageAlert,
  resolveOriginatingTabId,
  ensureCatalogue,
};


