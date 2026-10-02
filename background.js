import { evaluate } from "./lib/scoring.js";
import { buildNotificationTitle, buildNotificationMessage } from "./lib/alert.js";
import { getHostname, resolveFilename } from "./lib/heuristics.js";
import { getHistory, addHistoryEntry, clearHistory } from "./lib/history.js";
// A. Constants

const DEFAULT_SETTINGS = {
  enabled: true,
  useBackend: false,
  backendUrl: "",
  autoResumeSafe: true,
  trustedDomains: [],
  sensitivity: "medium",
};

const DEBUG_ANALYSIS_DELAY_MS = 2000;
const DEBUG_FORCE_ERROR = false;
const DECISION_TIMEOUT_MS = 120000;
const LOG_PREFIX = "[DG]";

const activeResolutions = new Set();

// B. Storage helpers

/**
 * Returns the configured settings merged with safe defaults.
 *
 * @returns {Promise<Record<string, unknown>>} The current settings.
 */
async function getSettings() {
  try {
    const { settings = {} } = await chrome.storage.local.get("settings");
    return {
      ...DEFAULT_SETTINGS,
      ...(settings && typeof settings === "object" ? settings : {}),
    };
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
    const next = {
      ...current,
      ...(partial && typeof partial === "object" ? partial : {}),
    };
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
      log("analysis started", downloadId, "Step 1 placeholder");
      const result = await analyzeDownload(item, settings);
      log("analysis finished", downloadId, `verdict=${result.verdict}, source=${result.source}`);

      let latestItem;
      try {
        [latestItem] = await chrome.downloads.search({ id: downloadId });
      } catch (searchError) {
        log("post-analysis search failed", downloadId, searchError?.message || String(searchError));
      }

      if (!latestItem || latestItem.state !== "in_progress") {
        log(
          "analysis result ignored",
          downloadId,
          `state=${latestItem?.state || "not found"}`,
        );
        outcome = "ignored";
        return;
      }

      if (result && (result.verdict === "suspicious" || result.verdict === "dangerous")) {
        outcome = await holdDownload(item, result);
      } else {
        outcome = "resumed";
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

      if (outcome !== "held") {
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
              title: buildNotificationTitle(verdict),
              message: buildNotificationMessage(filename, host, result?.reasons || []),
              requireInteraction: true,
              buttons: [
                { title: "Cancel download" },
                { title: "Allow anyway" },
              ],
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
 * Simulates asynchronous analysis without applying any security rules.
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

  return {
    downloadId: item.id,
    score: verdictResult.score,
    verdict: verdictResult.verdict,
    reasons: verdictResult.reasons,
    source: verdictResult.source,
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
    // A held download has a verdict stored in its session entry. The notification
    // and alarm were created before the restart and are still live. Leave the
    // session entry intact so resolveDecision() can still act on button/timeout.
    if (data && typeof data.verdict === "string" && data.verdict) {
      log("recovery skipped (held)", downloadId, `verdict=${data.verdict}`);
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
  let hasPending = false;
  try {
    const data = await chrome.storage.session.get(key);
    hasPending = !!(data && data[key]);
  } catch (_e) {
    // ignore
  }
  if (!hasPending) {
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
      try {
        await chrome.downloads.resume(downloadId);
        log("decision allow", downloadId, cause);
      } catch (resumeError) {
        log("decision allow resume failed", downloadId, resumeError?.message || String(resumeError));
        activeResolutions.delete(downloadId);
        return { ok: false, error: resumeError?.message || String(resumeError) };
      }
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

// TODO(step 2): decision history + notifications
// TODO(step 3): redirect tracking + typosquat detection
// TODO(step 4): heuristics, scoring, and optional backend analysis
// TODO(step 5): popup, options, and content-script integration

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
  resolveDecision,
  activeResolutions,
  recoverPendingDownloads,
  onDownloadsChanged,
  markPending,
  clearPending,
  pendingKey,
  getHistory,
  addHistoryEntry,
  clearHistory,
};

