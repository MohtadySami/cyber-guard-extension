import { evaluate, SCORING_CONSTANTS } from "./lib/scoring.js";

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
const LOG_PREFIX = "[DG]";

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
      // #region agent log
      await fetch('http://127.0.0.1:7471/ingest/c65017e1-d2c9-452e-a774-e91be2c5aea3',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'307455'},body:JSON.stringify({sessionId:'307455',runId:'post-fix',hypothesisId:'D',location:'background.js:handleNewDownload',message:'analysis finished',data:{downloadId,verdict:result.verdict,source:result.source,score:result.score},timestamp:Date.now()})}).catch(()=>{});
      // #endregion
    } catch (analysisError) {
      log("analysis error", downloadId, analysisError?.message || String(analysisError));
      // #region agent log
      await fetch('http://127.0.0.1:7471/ingest/c65017e1-d2c9-452e-a774-e91be2c5aea3',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'307455'},body:JSON.stringify({sessionId:'307455',runId:'post-fix',hypothesisId:'D',location:'background.js:handleNewDownload',message:'analysis threw',data:{downloadId,errorName:analysisError?.name,errorMessage:analysisError?.message||String(analysisError)},timestamp:Date.now()})}).catch(()=>{});
      // #endregion
      const result = { verdict: "safe", source: "error-fallback" };
      log("analysis fallback", downloadId, `verdict=${result.verdict}, source=${result.source}`);
    }
  } catch (error) {
    log("handler error", downloadId, error?.message || String(error));
  } finally {
    if (shouldSettle) {
      try {
        log("resume requested", downloadId);
        await chrome.downloads.resume(downloadId);
        log("resumed", downloadId);
      } catch (resumeError) {
        log("resume failed", downloadId, resumeError?.message || String(resumeError));
      }
    }

    const pendingCleared = await clearPending(downloadId);
    log(
      "pending cleared",
      downloadId,
      pendingCleared ? "session state removed" : "session state cleanup failed",
    );
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
  // #region agent log
  await fetch('http://127.0.0.1:7471/ingest/c65017e1-d2c9-452e-a774-e91be2c5aea3',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'307455'},body:JSON.stringify({sessionId:'307455',runId:'post-fix',hypothesisId:'A,B,E',location:'background.js:analyzeDownload:entry',message:'analyzeDownload entry',data:{downloadId:item?.id,hasEvaluate:typeof evaluate==='function',enforce:SCORING_CONSTANTS?.ENFORCE_VERDICTS,settingsType:typeof settings,ctxFilename:ctx.filename,ctxUrl:ctx.url,ctxFinalUrl:ctx.finalUrl},timestamp:Date.now()})}).catch(()=>{});
  // #endregion
  log("analysis delay", item.id, `${DEBUG_ANALYSIS_DELAY_MS}ms`);
  await new Promise((resolve) => setTimeout(resolve, DEBUG_ANALYSIS_DELAY_MS));

  if (DEBUG_FORCE_ERROR) {
    throw new Error("DEBUG_FORCE_ERROR is enabled");
  }

  let heuristicReasons = [];
  try {
    const verdictResult = evaluate(ctx, { sensitivity: "medium" });
    heuristicReasons = verdictResult.reasons;
    // #region agent log
    await fetch('http://127.0.0.1:7471/ingest/c65017e1-d2c9-452e-a774-e91be2c5aea3',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'307455'},body:JSON.stringify({sessionId:'307455',runId:'post-fix',hypothesisId:'C',location:'background.js:analyzeDownload:heuristics',message:'first evaluate ok',data:{downloadId:item.id,reasonCount:heuristicReasons.length,score:verdictResult.score,source:verdictResult.source},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
  } catch (heuristicError) {
    log("heuristics error", item.id, heuristicError?.message || String(heuristicError));
    // #region agent log
    await fetch('http://127.0.0.1:7471/ingest/c65017e1-d2c9-452e-a774-e91be2c5aea3',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'307455'},body:JSON.stringify({sessionId:'307455',runId:'post-fix',hypothesisId:'C',location:'background.js:analyzeDownload:heuristics',message:'first evaluate threw',data:{downloadId:item.id,errorName:heuristicError?.name,errorMessage:heuristicError?.message||String(heuristicError)},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
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
  let enforceVerdicts = false;
  try {
    enforceVerdicts = SCORING_CONSTANTS.ENFORCE_VERDICTS === true;
    verdictResult = evaluate(ctx, settings);
    // #region agent log
    await fetch('http://127.0.0.1:7471/ingest/c65017e1-d2c9-452e-a774-e91be2c5aea3',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'307455'},body:JSON.stringify({sessionId:'307455',runId:'post-fix',hypothesisId:'A',location:'background.js:analyzeDownload:scoring',message:'second evaluate ok',data:{downloadId:item.id,verdict:verdictResult.verdict,score:verdictResult.score,source:verdictResult.source,settingsType:typeof settings},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
  } catch (scoringError) {
    log("scoring error", item.id, scoringError?.message || String(scoringError));
    // #region agent log
    await fetch('http://127.0.0.1:7471/ingest/c65017e1-d2c9-452e-a774-e91be2c5aea3',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'307455'},body:JSON.stringify({sessionId:'307455',runId:'post-fix',hypothesisId:'A',location:'background.js:analyzeDownload:scoring',message:'second evaluate threw',data:{downloadId:item.id,errorName:scoringError?.name,errorMessage:scoringError?.message||String(scoringError),settingsType:typeof settings},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
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
    !enforceVerdicts &&
    (verdictResult.verdict === "suspicious" || verdictResult.verdict === "dangerous")
  ) {
    log(
      "would have held",
      item.id,
      `(${verdictResult.verdict}) score=${verdictResult.score}`,
    );
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

  for (const { id: downloadId } of pendingDownloads) {
    try {
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
    } finally {
      const pendingCleared = await clearPending(downloadId);
      log(
        "recovery cleared",
        downloadId,
        pendingCleared ? "session state removed" : "session state cleanup failed",
      );
    }
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

  if (["GET_HISTORY", "ANALYZE_URL", "USER_DECISION"].includes(message.type)) {
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

void recoverPendingDownloads("worker startup");
