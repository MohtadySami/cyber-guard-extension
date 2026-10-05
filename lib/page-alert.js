// One-shot page threat alert.
//
// Injected with chrome.scripting.executeScript() into the tab a download came FROM,
// at the moment analysis completes (SAFE green, SUSPICIOUS amber, DANGEROUS red).
// It is NOT a permanently registered content script: nothing runs on any page until
// a download is analyzed and the user has granted the optional pageAlerts permission.
//
// Privacy posture:
//   * Receives only a verdict, a file name and a reason. No URL, no page
//     content, no browsing history is sent to the page or stored.
//   * The injected function is self-contained and runs in the ISOLATED world,
//     so it cannot reach extension APIs and the page cannot reach it directly.
//   * The alert is non-blocking: the page stays fully usable.

import { t, localizeReason, normalizeLanguage } from "./i18n.js";

/** Maximum filename length rendered in the alert. */
const MAX_FILENAME = 100;

/** ID of the host element the alert is rendered into. */
export const ALERT_HOST_ID = "cyber-guard-page-alert";

/** Optional permissions this feature needs. Nothing is granted by default. */
export const PAGE_ALERT_PERMISSION = Object.freeze({
  permissions: Object.freeze(["scripting"]),
  origins: Object.freeze(["http://*/*", "https://*/*"]),
});

/**
 * True when the user has granted the optional permission needed to inject.
 *
 * @param {{contains?: Function}} permissionsApi - chrome.permissions.
 * @returns {Promise<boolean>} Whether injection is permitted.
 */
export async function hasPageAlertPermission(permissionsApi) {
  const api = permissionsApi && typeof permissionsApi.contains === "function"
    ? permissionsApi
    : null;
  if (!api) {
    return false;
  }
  try {
    const granted = await api.contains(PAGE_ALERT_PERMISSION);
    return granted === true;
  } catch {
    return false;
  }
}

/**
 * Decides whether a page alert is allowed for a download.
 *
 * Safe, suspicious, and dangerous verdicts on a valid web tab qualify.
 *
 * @param {{verdict?: string, tabId?: number}} params - Download facts.
 * @returns {boolean} True when an alert may be shown.
 */
export function shouldAlertOnPage(params) {
  const safe = params && typeof params === "object" ? params : {};
  const verdict = safe.verdict || "safe";
  if (verdict !== "dangerous" && verdict !== "suspicious" && verdict !== "safe") {
    return false;
  }
  // tabId -1 means "not initiated by a web page" (e.g. a save dialog).
  return Number.isInteger(safe.tabId) && safe.tabId >= 0;
}

/**
 * Builds the localized payload handed to the injected script.
 *
 * @param {{verdict?: string, filename?: string, reason?: object, reasonText?: string, language?: string}} params
 * @returns {{headline: string, body: string, fileLabel: string, filename: string, reason: string, dismiss: string, language: string, verdict: string, icon: string}}
 */
export function buildAlertPayload(params) {
  const safe = params && typeof params === "object" ? params : {};
  const language = normalizeLanguage(safe.language);
  const filename =
    typeof safe.filename === "string" && safe.filename
      ? safe.filename.slice(0, MAX_FILENAME)
      : "";
  const verdict = safe.verdict === "dangerous" || safe.verdict === "suspicious" ? safe.verdict : "safe";

  const reason =
    typeof safe.reasonText === "string" && safe.reasonText
      ? safe.reasonText
      : localizeReason(safe.reason, language);

  let headline = "";
  let body = "";
  let icon = "✓";

  if (verdict === "dangerous") {
    headline = t("alertHeadlineDangerous", language) || t("alertHeadline", language);
    body = t("alertBodyDangerous", language) || t("alertBody", language);
    icon = "⚠️";
  } else if (verdict === "suspicious") {
    headline = t("alertHeadlineSuspicious", language);
    body = t("alertBodySuspicious", language);
    icon = "⚠️";
  } else {
    headline = t("alertHeadlineSafe", language);
    body = t("alertBodySafe", language);
    icon = "✓";
  }

  return {
    headline: headline || "CYBER GUARD",
    body: body || "",
    fileLabel: t("alertFilename", language),
    filename,
    reason,
    dismiss: t("alertDismiss", language),
    language,
    verdict,
    icon,
  };
}

/**
 * The function serialized into the page by chrome.scripting.executeScript().
 *
 * @param {object} payload - Output of buildAlertPayload().
 * @returns {boolean} True when the alert was rendered.
 */
export function renderPageAlert(payload) {
  const data = payload && typeof payload === "object" ? payload : {};
  const verdict = data.verdict === "dangerous" || data.verdict === "suspicious" ? data.verdict : "safe";

  const existing = document.getElementById("cyber-guard-page-alert");
  if (existing && existing.parentNode) {
    existing.parentNode.removeChild(existing);
  }

  const host = document.createElement("div");
  host.id = "cyber-guard-page-alert";
  host.style.cssText = [
    "position:fixed",
    "top:24px",
    "left:50%",
    "transform:translateX(-50%)",
    "z-index:2147483647",
    "pointer-events:none",
    "font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif",
  ].join(";");

  const root = host.attachShadow ? host.attachShadow({ mode: "closed" }) : null;
  if (!root) {
    return false;
  }

  const rtl = data.language === "ar";
  const isDangerous = verdict === "dangerous";
  const isSuspicious = verdict === "suspicious";

  // Color tokens per verdict
  const themeColor = isDangerous ? "#ef4444" : isSuspicious ? "#f59e0b" : "#10b981";
  const headColor = isDangerous ? "#fca5a5" : isSuspicious ? "#fde68a" : "#6ee7b7";
  const shadowGlow = isDangerous
    ? "rgba(239, 68, 68, 0.45)"
    : isSuspicious
    ? "rgba(245, 158, 11, 0.35)"
    : "rgba(16, 185, 129, 0.35)";
  const vignetteShadow = isDangerous
    ? "inset 0 0 65px rgba(239, 68, 68, 0.35)"
    : isSuspicious
    ? "inset 0 0 60px rgba(245, 158, 11, 0.25)"
    : "inset 0 0 60px rgba(16, 185, 129, 0.25)";

  const style = document.createElement("style");
  style.textContent = [
    ":host{all:initial}",
    "*,*::before,*::after{box-sizing:border-box}",
    `.vignette{position:fixed;inset:0;box-shadow:${vignetteShadow};pointer-events:none;z-index:-1;animation:cg-fade 300ms ease-out forwards}`,
    "@keyframes cg-fade{from{opacity:0}to{opacity:1}}",
    ".wrap{position:relative;display:flex;justify-content:center}",
    ".box{pointer-events:auto;width:min(520px,92vw);background:#0b1120;color:#f8fafc;",
    `border:1.5px solid ${themeColor};border-radius:14px;padding:20px 24px;`,
    `box-shadow:0 16px 48px ${shadowGlow}, 0 0 20px ${shadowGlow};`,
    "opacity:0;transform:translateY(-14px) scale(0.96);",
    "animation:cg-in 260ms cubic-bezier(0.16,1,0.3,1) forwards}",
    "@keyframes cg-in{to{opacity:1;transform:none}}",
    ".badge-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}",
    ".brand{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:800;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8}",
    ".brand-icon{display:inline-block;width:8px;height:8px;border-radius:50%;background:" + themeColor + ";box-shadow:0 0 8px " + themeColor + "}",
    ".head{display:flex;align-items:center;gap:12px;font-size:16px;font-weight:800;letter-spacing:.02em;color:" + headColor + "}",
    ".icon{font-size:22px;line-height:1;display:inline-flex;align-items:center;justify-content:center}",
    ".body{margin:10px 0 0;font-size:13.5px;line-height:1.55;color:#e2e8f0}",
    ".file{margin-top:10px;font-size:12.5px;color:#94a3b8;background:#1e293b;padding:8px 12px;border-radius:8px;border:1px solid #334155;overflow-wrap:anywhere}",
    ".file b{color:#f1f5f9;font-weight:600}",
    ".reason{margin-top:8px;font-size:12.5px;font-weight:500;color:" + themeColor + ";overflow-wrap:anywhere}",
    ".actions{margin-top:16px;display:flex;gap:10px;justify-content:flex-end}",
    "button{pointer-events:auto;font:inherit;font-size:12px;font-weight:600;cursor:pointer;",
    "background:#1e293b;color:#f8fafc;border:1px solid #475569;border-radius:7px;padding:7px 16px;transition:all 0.15s}",
    "button:hover{background:#334155;border-color:#64748b}",
    "button:focus-visible{outline:2px solid " + themeColor + ";outline-offset:2px}",
    "@media (prefers-reduced-motion: reduce){.box,.vignette{animation:none;opacity:1;transform:none}}",
  ].join("");

  const wrap = document.createElement("div");
  wrap.className = "wrap";

  const vignette = document.createElement("div");
  vignette.className = "vignette";

  const box = document.createElement("div");
  box.className = "box";
  box.setAttribute("role", "alert");
  box.setAttribute("aria-live", "assertive");
  if (rtl) {
    box.setAttribute("dir", "rtl");
    box.setAttribute("lang", "ar");
  }

  // Top branding row
  const badgeRow = document.createElement("div");
  badgeRow.className = "badge-row";
  const brand = document.createElement("div");
  brand.className = "brand";
  const brandDot = document.createElement("span");
  brandDot.className = "brand-icon";
  const brandText = document.createElement("span");
  brandText.textContent = "CYBER GUARD";
  brand.appendChild(brandDot);
  brand.appendChild(brandText);
  badgeRow.appendChild(brand);
  box.appendChild(badgeRow);

  // Main headline row
  const head = document.createElement("div");
  head.className = "head";
  const icon = document.createElement("span");
  icon.className = "icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = String(data.icon || (isDangerous || isSuspicious ? "⚠️" : "✓"));
  const headText = document.createElement("span");
  headText.textContent = String(data.headline || "");
  head.appendChild(icon);
  head.appendChild(headText);
  box.appendChild(head);

  // Body text
  const body = document.createElement("p");
  body.className = "body";
  body.textContent = String(data.body || "");
  box.appendChild(body);

  if (data.filename) {
    const file = document.createElement("div");
    file.className = "file";
    const label = document.createElement("b");
    label.textContent = String(data.fileLabel || "") + ": ";
    file.appendChild(label);
    file.appendChild(document.createTextNode(String(data.filename)));
    box.appendChild(file);
  }

  if (data.reason) {
    const reason = document.createElement("div");
    reason.className = "reason";
    reason.textContent = String(data.reason);
    box.appendChild(reason);
  }

  const actions = document.createElement("div");
  actions.className = "actions";
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.textContent = String(data.dismiss || "Dismiss");

  const removeAlert = () => {
    if (host.parentNode) {
      host.parentNode.removeChild(host);
    }
  };

  dismiss.addEventListener("click", removeAlert);
  actions.appendChild(dismiss);
  box.appendChild(actions);

  wrap.appendChild(box);
  root.appendChild(style);
  root.appendChild(vignette);
  root.appendChild(wrap);
  (document.body || document.documentElement).appendChild(host);

  // Auto-dismiss timers: SAFE = 5s, SUSPICIOUS = 6s, DANGEROUS = 9s
  const autoDismissDelay = verdict === "safe" ? 5000 : verdict === "suspicious" ? 6000 : 9000;
  let timerId = setTimeout(removeAlert, autoDismissDelay);

  // Hovering pauses dismissal so user can read the warning
  box.addEventListener("mouseenter", () => {
    clearTimeout(timerId);
  });
  box.addEventListener("mouseleave", () => {
    clearTimeout(timerId);
    timerId = setTimeout(removeAlert, autoDismissDelay);
  });

  return true;
}
