// Popup UI for Cyber Guard.
// DOM wiring only; pure helpers live in ./lib/popup-core.js so they can be
// unit tested without a browser.
import { sendMessage, getVerdictPresentation, toHistoryRow, buildSettingsPatch } from "./lib/popup-core.js";

const STRINGS = {
  statusActive: "حماية نشطة",
  statusOff: "الحماية متوقفة",
  saveSuccess: "تم حفظ الإعدادات بنجاح",
  saveError: "فشل في حفظ الإعدادات",
  loadError: "فشل في تحميل الإعدادات",
  noHistory: "لا توجد عمليات فحص حالية",
};

const statusBadge = document.getElementById("statusBadge");
const statusText = document.getElementById("statusText");
const sensitivitySelect = document.getElementById("sensitivitySelect");
const enabledToggle = document.getElementById("enabledToggle");
const saveBtn = document.getElementById("saveBtn");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const msgText = document.getElementById("msgText");
const logsList = document.getElementById("logsList");

function setStatus(enabled) {
  if (enabled) {
    statusBadge.classList.add("active");
    statusBadge.classList.remove("off");
    statusText.textContent = STRINGS.statusActive;
  } else {
    statusBadge.classList.remove("active");
    statusBadge.classList.add("off");
    statusText.textContent = STRINGS.statusOff;
  }
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
  const sens = settings.sensitivity;
  if (sens === "low" || sens === "medium" || sens === "high") {
    sensitivitySelect.value = sens;
  } else {
    sensitivitySelect.value = "medium";
  }
  enabledToggle.checked = settings.enabled !== false;
  setStatus(enabledToggle.checked);
}

function createLogItem(entry) {
  const row = toHistoryRow(entry);

  const li = document.createElement("li");
  li.classList.add("log-item");

  const left = document.createElement("div");

  const filename = document.createElement("div");
  filename.textContent = row.filename;
  left.appendChild(filename);

  const meta = document.createElement("div");
  meta.textContent = row.meta;
  left.appendChild(meta);

  const right = document.createElement("div");
  const presentation = getVerdictPresentation(row.verdict);
  if (presentation) {
    const badge = document.createElement("span");
    badge.classList.add("verdict-badge", presentation.className);
    badge.textContent = presentation.label;
    right.appendChild(badge);
  }

  li.appendChild(left);
  li.appendChild(right);
  return li;
}

function appendEmptyRow() {
  const empty = document.createElement("li");
  empty.classList.add("log-item", "empty");
  empty.textContent = STRINGS.noHistory;
  logsList.appendChild(empty);
}

async function loadSettings() {
  const resp = await sendMessage({ type: "GET_SETTINGS" });
  if (resp && resp.ok && resp.settings) {
    populateForm(resp.settings);
    setMessage("", null);
    saveBtn.disabled = false;
  } else {
    setMessage(STRINGS.loadError, "error");
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
    }),
  });
  if (resp && resp.ok) {
    if (resp.settings) {
      populateForm(resp.settings);
    }
    setMessage(STRINGS.saveSuccess, "success");
  } else {
    const err = resp && resp.error ? resp.error : STRINGS.saveError;
    setMessage(err, "error");
  }
}

async function clearHistory() {
  await sendMessage({ type: "CLEAR_HISTORY" });
  await loadHistory();
}

saveBtn.addEventListener("click", () => {
  void saveSettings().catch(() => {
    setMessage(STRINGS.saveError, "error");
  });
});

clearHistoryBtn.addEventListener("click", () => {
  void clearHistory().catch(() => {
    setMessage(STRINGS.saveError, "error");
  });
});

enabledToggle.addEventListener("change", () => {
  setStatus(enabledToggle.checked);
});

function init() {
  void loadSettings().catch(() => {
    setMessage(STRINGS.loadError, "error");
  });
  void loadHistory().catch(() => {
    // History is best-effort in the popup; the settings row already reports errors.
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") {
      return;
    }
    if (changes.history) {
      void loadHistory().catch(() => {});
    }
    if (changes.settings) {
      void loadSettings().catch(() => {
        setMessage(STRINGS.loadError, "error");
      });
    }
  });
}
