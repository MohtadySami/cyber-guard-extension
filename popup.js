// Popup UI for Cyber Guard.
// DOM wiring only; pure helpers live in ./lib/popup-core.js, ./lib/i18n.js and
// ./lib/threat/engine.js so they can be unit tested without a browser.
import {
  sendMessage,
  getVerdictPresentation,
  toHistoryRow,
  buildSettingsPatch,
  resolveUiLanguage,
} from "./lib/popup-core.js";
import {
  t,
  getDirection,
  getLocale,
  getLanguageName,
  loadCatalogue,
  SUPPORTED_LANGUAGES,
} from "./lib/i18n.js";
import { stateMessageKey, THREAT_STATES } from "./lib/threat/engine.js";
import { mountRadar, setRadarState } from "./lib/radar-ui.js";
import { PAGE_ALERT_PERMISSION, hasPageAlertPermission } from "./lib/page-alert.js";

const statusBadge = document.getElementById("statusBadge");
const statusText = document.getElementById("statusText");
const radar = document.getElementById("radar");
const container = document.getElementById("container");
const sensitivitySelect = document.getElementById("sensitivitySelect");
const languageSelect = document.getElementById("languageSelect");
const enabledToggle = document.getElementById("enabledToggle");
const pageAlertsToggle = document.getElementById("pageAlertsToggle");
const saveBtn = document.getElementById("saveBtn");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const msgText = document.getElementById("msgText");
const logsList = document.getElementById("logsList");

let currentLanguage = resolveUiLanguage();

// The mounted 3D radar element. `radar` is the header slot it lives in; the
// state attributes belong on the radar itself, because that is the node the CSS
// custom properties are declared on.
let radarElement = null;

/**
 * Loads the message catalogue for a language from the packaged _locales
 * directory. `chrome.i18n.getMessage()` resolves against the BROWSER locale and
 * has no API for requesting a specific language (crbug/660704), so the runtime
 * selector reads the catalogues directly.
 *
 * @param {string} language - Language code.
 * @returns {Promise<void>} Resolves when the catalogue is ready or failed.
 */
async function ensureCatalogue(language) {
  await loadCatalogue(language, async (path) => {
    const response = await fetch(chrome.runtime.getURL(path));
    if (!response.ok) {
      throw new Error(`catalogue ${path} -> ${response.status}`);
    }
    return await response.json();
  });
}

/** Builds the language selector options, each labelled in its own language. */
function populateLanguages() {
  languageSelect.textContent = "";
  for (const code of SUPPORTED_LANGUAGES) {
    const option = document.createElement("option");
    option.value = code;
    option.textContent = getLanguageName(code);
    languageSelect.appendChild(option);
  }
}

/**
 * Applies a language to the whole popup: <html lang/dir> plus every element
 * carrying a data-i18n key. Document direction is driven only from here.
 *
 * @param {string} language - Stored language value.
 */
function applyLanguage(language) {
  currentLanguage = resolveUiLanguage(language);
  document.documentElement.lang = currentLanguage;
  document.documentElement.dir = getDirection(currentLanguage);

  for (const element of document.querySelectorAll("[data-i18n]")) {
    const key = element.getAttribute("data-i18n");
    if (key) {
      element.textContent = t(key, currentLanguage);
    }
  }
}

/**
 * Renders one of the explicit visual states: secure, analyzing, threat or off.
 *
 * @param {string} state - A THREAT_STATES value or "off".
 */
function setThreatState(state) {
  const value = state || THREAT_STATES.SECURE;
  // Presentation only: the radar renders the state, it never computes one.
  setRadarState(radarElement || radar, value);
  statusBadge.dataset.state = value;
  // Drive the whole-popup theme from the same state value.
  if (container) {
    container.dataset.theme = value;
  }
  statusText.textContent =
    value === "off" ? t("stateOff", currentLanguage) : t(stateMessageKey(value), currentLanguage);
}

/** Reflects the enable toggle: off state, or secure when protection is on. */
function setEnabledState(enabled) {
  if (!enabled) {
    setThreatState("off");
    return;
  }
  // Protection on: the radar shows the live threat state from the background,
  // which defaults to secure.
  setThreatState(THREAT_STATES.SECURE);
}

function setMessage(text, type) {
  msgText.textContent = text || "";
  msgText.classList.remove("success", "error");
  if (type === "success") {
    msgText.classList.add("success");
  } else if (type === "error") {
    msgText.classList.add("error");
  }
}

function populateForm(settings) {
  if (!settings || typeof settings !== "object") {
    return;
  }
  const previousLanguage = currentLanguage;
  applyLanguage(settings.language);
  languageSelect.value = currentLanguage;

  const sens = settings.sensitivity;
  sensitivitySelect.value =
    sens === "low" || sens === "medium" || sens === "high" ? sens : "medium";

  enabledToggle.checked = settings.enabled !== false;
  pageAlertsToggle.checked = settings.pageAlerts === true;
  if (pageAlertsToggle.checked) {
    const permissionsApi =
      typeof chrome !== "undefined" && chrome.permissions ? chrome.permissions : null;
    if (permissionsApi && typeof permissionsApi.contains === "function") {
      void hasPageAlertPermission(permissionsApi).then((granted) => {
        if (!granted && pageAlertsToggle.checked) {
          pageAlertsToggle.checked = false;
        }
      });
    }
  }
  setEnabledState(enabledToggle.checked);

  if (previousLanguage !== currentLanguage) {
    // Rendered rows carry the previous language's labels; re-render them.
    void loadHistory().catch(() => {});
  }
}

/**
 * Asks the background for the live threat state and renders it.
 * Falls back to the secure state so the popup never opens in a broken look.
 */
async function refreshThreatState() {
  if (!enabledToggle.checked) {
    setThreatState("off");
    return;
  }
  const resp = await sendMessage({ type: "GET_THREAT_STATE" });
  const state = resp && resp.ok && resp.state ? resp.state.state : THREAT_STATES.SECURE;
  setThreatState(state);
}

function createLogItem(entry) {
  const row = toHistoryRow(entry, currentLanguage);

  const li = document.createElement("li");
  li.classList.add("log-item");

  const left = document.createElement("div");

  const filename = document.createElement("div");
  filename.textContent = row.filename;
  left.appendChild(filename);

  const meta = document.createElement("div");
  meta.classList.add("log-meta");
  meta.textContent = row.meta;
  left.appendChild(meta);

  if (row.decisionLabel) {
    const decision = document.createElement("div");
    decision.classList.add("log-decision");
    decision.textContent = `${t("decisionPrefix", currentLanguage)}: ${row.decisionLabel}`;
    left.appendChild(decision);
  }

  const right = document.createElement("div");
  const presentation = getVerdictPresentation(row.verdict, currentLanguage);
  if (presentation) {
    const badge = document.createElement("span");
    badge.classList.add("verdict-badge", presentation.className);
    // Threat verdicts carry a warning glyph; safe does not.
    badge.textContent =
      row.verdict === "dangerous" || row.verdict === "suspicious"
        ? `⚠️ ${presentation.label}`
        : presentation.label;
    right.appendChild(badge);
  }

  li.appendChild(left);
  li.appendChild(right);
  return li;
}

function appendEmptyRow() {
  const empty = document.createElement("li");
  empty.classList.add("log-item", "empty");
  empty.textContent = t("noHistory", currentLanguage);
  logsList.appendChild(empty);
}

async function loadSettings() {
  const resp = await sendMessage({ type: "GET_SETTINGS" });
  if (resp && resp.ok && resp.settings) {
    populateForm(resp.settings);
    setMessage("", null);
    saveBtn.disabled = false;
    void refreshThreatState().catch(() => {});
  } else {
    setMessage(t("loadError", currentLanguage), "error");
    saveBtn.disabled = true;
  }
}

async function loadHistory() {
  const resp = await sendMessage({ type: "GET_HISTORY" });
  while (logsList.firstChild) {
    logsList.removeChild(logsList.firstChild);
  }
  const history = resp && resp.ok && Array.isArray(resp.history) ? resp.history : [];
  if (history.length === 0) {
    appendEmptyRow();
    return;
  }
  for (const entry of history) {
    logsList.appendChild(createLogItem(entry));
  }
}

async function saveSettings() {
  setMessage("", null);
  const resp = await sendMessage({
    type: "SET_SETTINGS",
    settings: buildSettingsPatch({
      sensitivity: sensitivitySelect.value,
      enabled: enabledToggle.checked,
      language: languageSelect.value,
      pageAlerts: pageAlertsToggle.checked,
    }),
  });
  if (resp && resp.ok) {
    if (resp.settings) {
      populateForm(resp.settings);
    }
    setMessage(t("saveSuccess", currentLanguage), "success");
  } else {
    const err = resp && resp.error ? resp.error : t("saveError", currentLanguage);
    setMessage(err, "error");
  }
}

/**
 * Requests the optional scripting permission for page alerts.
 *
 * Must be executed in the popup context (with user gesture) because
 * chrome.permissions.request cannot be called from a service worker in MV3.
 */
async function togglePageAlerts(enabled) {
  if (!enabled) {
    pageAlertsToggle.checked = false;
    await saveSettings();
    return;
  }
  let granted = false;
  try {
    const permissionsApi =
      typeof chrome !== "undefined" && chrome.permissions ? chrome.permissions : null;
    if (permissionsApi && typeof permissionsApi.request === "function") {
      granted = await permissionsApi.request(PAGE_ALERT_PERMISSION);
    }
  } catch (err) {
    console.error("Permission request error:", err);
    granted = false;
  }
  pageAlertsToggle.checked = Boolean(granted);
  setMessage(
    granted ? t("saveSuccess", currentLanguage) : t("pageAlertPermissionDenied", currentLanguage),
    granted ? "success" : "error",
  );
  await saveSettings();
}

async function clearHistory() {
  await sendMessage({ type: "CLEAR_HISTORY" });
  await loadHistory();
}

saveBtn.addEventListener("click", () => {
  void saveSettings().catch(() => {
    setMessage(t("saveError", currentLanguage), "error");
  });
});

clearHistoryBtn.addEventListener("click", () => {
  void clearHistory().catch(() => {
    setMessage(t("saveError", currentLanguage), "error");
  });
});

enabledToggle.addEventListener("change", () => {
  setEnabledState(enabledToggle.checked);
});

pageAlertsToggle.addEventListener("change", () => {
  void togglePageAlerts(pageAlertsToggle.checked).catch(() => {
    setMessage(t("saveError", currentLanguage), "error");
  });
});

// Live repaint in the newly chosen language, persisted through the normal
// settings round-trip so the choice survives reopening the popup.
languageSelect.addEventListener("change", () => {
  const previousLanguage = currentLanguage;
  void (async () => {
    await ensureCatalogue(languageSelect.value);
    applyLanguage(languageSelect.value);
    setEnabledState(enabledToggle.checked);
    // Re-populate so each option shows its name in the NEW language.
    populateLanguages();
    languageSelect.value = currentLanguage;
    if (previousLanguage !== currentLanguage) {
      await loadHistory().catch(() => {});
    }
    await saveSettings();
  })().catch(() => {
    setMessage(t("saveError", currentLanguage), "error");
  });
});

async function init() {
  radarElement = mountRadar(radar);
  setRadarState(radarElement || radar, THREAT_STATES.SECURE);
  // Load the catalogue BEFORE populating anything, or the language names render
  // as raw message keys on a cold open.
  await ensureCatalogue(currentLanguage).catch(() => {});
  populateLanguages();
  applyLanguage(currentLanguage);
  languageSelect.value = currentLanguage;

  await loadSettings().catch(() => {
    setMessage(t("loadError", currentLanguage), "error");
  });
  await loadHistory().catch(() => {
    // History is best-effort in the popup; the settings row already reports errors.
  });
  void refreshThreatState().catch(() => {});
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    void init();
  });
} else {
  void init();
}

if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") {
      return;
    }
    if (changes.history || changes.decisionHistory) {
      void loadHistory().catch(() => {});
    }
    if (changes.settings) {
      void loadSettings().catch(() => {
        setMessage(t("loadError", currentLanguage), "error");
      });
    }
  });
}
