// Alert utilities for notifications - pure, no chrome.* usage
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

export function buildNotificationTitle(verdict) {
  if (verdict === "dangerous") {
    return "Dangerous download";
  }
  return "Suspicious download";
}

export function buildNotificationMessage(filename, host, reasons) {
  const topReasons = topReasonsOf(reasons);
  const lines = [];
  if (filename) {
    lines.push(`File: ${truncateString(filename, 100)}`);
  }
  if (host) {
    lines.push(`Source: ${truncateString(host, 100)}`);
  }
  for (const r of topReasons) {
    if (r && r.text) {
      lines.push(truncateString(r.text, 200));
    }
  }
  return lines.join("\n");
}

/**
 * Title for the notification raised when a risky download finished before the
 * analysis could act on it, so it could never be paused.
 *
 * @param {string} verdict - "suspicious" or "dangerous".
 * @returns {string} The notification title.
 */
export function buildCompletedNotificationTitle(verdict) {
  if (verdict === "dangerous") {
    return "Dangerous file already downloaded";
  }
  return "Suspicious file already downloaded";
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
export function buildCompletedNotificationMessage(filename, host, reasons) {
  const topReasons = topReasonsOf(reasons);
  const lines = [
    "This file finished downloading before Cyber Guard could pause it.",
  ];
  if (filename) {
    lines.push(`File: ${truncateString(filename, 100)}`);
  }
  if (host) {
    lines.push(`Source: ${truncateString(host, 100)}`);
  }
  for (const r of topReasons) {
    if (r && r.text) {
      lines.push(truncateString(r.text, 200));
    }
  }
  lines.push('Choose "Delete file" to remove it from disk, or "Keep file" to allow it.');
  return lines.join("\n");
}
