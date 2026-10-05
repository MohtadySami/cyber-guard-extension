// Alert utilities for notifications - pure, no chrome.* usage
//
// Notification text is presentation only. Every builder takes the resolved UI
// language; when it is omitted the language layer's default (English) applies.
// All wording comes from the _locales catalogues via lib/i18n.js.
import { t, localizeReason } from "./i18n.js";

export function truncateString(str, maxLength) {
  if (typeof str !== "string") {
    return "";
  }
  if (str.length <= maxLength) {
    return str;
  }
  return str.slice(0, maxLength - 3) + "...";
}

function topReasonsOf(reasons) {
  return Array.isArray(reasons)
    ? reasons
        .filter((r) => r && typeof r.points === "number" && r.points > 0)
        .sort((a, b) => (b.points || 0) - (a.points || 0))
        .slice(0, 3)
    : [];
}

/** Localized reason lines, heaviest first. */
function reasonLines(reasons, language) {
  const lines = [];
  for (const r of topReasonsOf(reasons)) {
    const text = localizeReason(r, language);
    if (text) {
      lines.push(truncateString(text, 200));
    }
  }
  return lines;
}

/**
 * @param {string} verdict - "dangerous" or "suspicious".
 * @param {string} [language] - UI language; defaults to English.
 * @returns {string} The notification title.
 */
export function buildNotificationTitle(verdict, language) {
  if (verdict === "dangerous") {
    return t("notifyDangerousTitle", language);
  }
  return t("notifySuspiciousTitle", language);
}

/**
 * @param {string} filename - The downloaded file name.
 * @param {string} host - The source hostname.
 * @param {Array} reasons - Heuristic reasons.
 * @param {string} [language] - UI language.
 * @returns {string} The notification message.
 */
export function buildNotificationMessage(filename, host, reasons, language) {
  const lines = [];
  if (filename) {
    lines.push(`${t("notifFile", language)}: ${truncateString(filename, 100)}`);
  }
  if (host) {
    lines.push(`${t("notifSource", language)}: ${truncateString(host, 100)}`);
  }
  lines.push(...reasonLines(reasons, language));
  return lines.join("\n");
}

/**
 * Title for the notification raised when a risky download finished before the
 * analysis could act on it, so it could never be paused.
 *
 * @param {string} verdict - "suspicious" or "dangerous".
 * @returns {string} The notification title.
 */
export function buildCompletedNotificationTitle(verdict, language) {
  if (verdict === "dangerous") {
    return t("notifyCompletedDangerousTitle", language);
  }
  return t("notifyCompletedSuspiciousTitle", language);
}

/**
 * Message for the completed-but-risky notification. Explains that the file
 * could not be paused and states both available actions.
 *
 * @param {string} filename - The downloaded file name.
 * @param {string} host - The source hostname.
 * @param {Array<{points: number, text?: string}>} reasons - Heuristic reasons.
 * @returns {string} The notification message.
 */
export function buildCompletedNotificationMessage(filename, host, reasons, language) {
  const lines = [t("notifCompletedIntro", language)];
  if (filename) {
    lines.push(`${t("notifFile", language)}: ${truncateString(filename, 100)}`);
  }
  if (host) {
    lines.push(`${t("notifSource", language)}: ${truncateString(host, 100)}`);
  }
  lines.push(...reasonLines(reasons, language));
  lines.push(t("notifCompletedActionHint", language));
  return lines.join("\n");
}
