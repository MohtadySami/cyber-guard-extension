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

export function buildNotificationTitle(verdict) {
  if (verdict === "dangerous") {
    return "Dangerous download";
  }
  return "Suspicious download";
}

export function buildNotificationMessage(filename, host, reasons) {
  const topReasons = Array.isArray(reasons)
    ? reasons
        .filter((r) => r && typeof r.points === "number" && r.points > 0)
        .sort((a, b) => (b.points || 0) - (a.points || 0))
        .slice(0, 3)
    : [];
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
