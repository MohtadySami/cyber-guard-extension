/**
 * Decision history helper functions.
 * Stored persistently in chrome.storage.local under "decisionHistory".
 */

export const HISTORY_STORAGE_KEY = "decisionHistory";
const MAX_HISTORY_ITEMS = 100;

let historyWriteQueue = Promise.resolve();

/**
 * Reads the decision history array from chrome.storage.local.
 * Always returns a valid array.
 *
 * @returns {Promise<Array<Record<string, unknown>>>}
 */
export async function getHistory() {
  try {
    const data = await chrome.storage.local.get(HISTORY_STORAGE_KEY);
    const raw = data ? data[HISTORY_STORAGE_KEY] : null;
    if (Array.isArray(raw)) {
      return raw.filter((item) => item && typeof item === "object");
    }
    return [];
  } catch (error) {
    console.error("[DG] history read failed", error);
    return [];
  }
}

/**
 * Internal helper to format and append entry safely.
 *
 * @param {Record<string, unknown>} entry
 * @returns {Promise<Array<Record<string, unknown>>>}
 */
async function appendEntryInternal(entry) {
  if (!entry || typeof entry !== "object") {
    return await getHistory();
  }
  const current = await getHistory();
  const downloadId =
    typeof entry.downloadId === "number"
      ? entry.downloadId
      : typeof entry.id === "number"
        ? entry.id
        : 0;
  const hostname =
    typeof entry.hostname === "string"
      ? entry.hostname
      : typeof entry.host === "string"
        ? entry.host
        : "";

  const formatted = {
    downloadId,
    timestamp: typeof entry.timestamp === "number" ? entry.timestamp : Date.now(),
    filename: typeof entry.filename === "string" ? entry.filename : "",
    url: typeof entry.url === "string" ? entry.url : "",
    hostname,
    verdict: typeof entry.verdict === "string" ? entry.verdict : "unknown",
    score: typeof entry.score === "number" ? entry.score : 0,
    decision: typeof entry.decision === "string" ? entry.decision : "allow",
    cause: typeof entry.cause === "string" ? entry.cause : "unknown",
    source: typeof entry.source === "string" ? entry.source : "local",
  };
  const next = [formatted, ...current].slice(0, MAX_HISTORY_ITEMS);
  await chrome.storage.local.set({ [HISTORY_STORAGE_KEY]: next });
  return next;
}

/**
 * Serialized save of a decision history entry to chrome.storage.local (newest first).
 * Uses a promise queue to prevent concurrent read/modify/write race conditions.
 *
 * @param {Record<string, unknown>} entry - History record.
 * @returns {Promise<Array<Record<string, unknown>>>} Updated history list.
 */
export async function addHistoryEntry(entry) {
  const resultPromise = historyWriteQueue
    .then(() => appendEntryInternal(entry))
    .catch(async (err) => {
      console.error("[DG] history write queue error", err);
      return await getHistory();
    });
  historyWriteQueue = resultPromise.then(
    () => {},
    () => {},
  );
  return await resultPromise;
}

/**
 * Clears the decision history from chrome.storage.local.
 *
 * @returns {Promise<boolean>}
 */
export async function clearHistory() {
  const resultPromise = historyWriteQueue
    .then(async () => {
      await chrome.storage.local.set({ [HISTORY_STORAGE_KEY]: [] });
      return true;
    })
    .catch(async (error) => {
      console.error("[DG] history clear failed", error);
      return false;
    });
  historyWriteQueue = resultPromise.then(
    () => {},
    () => {},
  );
  return await resultPromise;
}
