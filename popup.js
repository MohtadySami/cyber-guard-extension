// Popup UI for Cyber Guard
const STRINGS = {
  statusActive: "حماية نشطة",
  statusOff: "الحماية متوقفة",
  saveSuccess: "تم حفظ الإعدادات بنجاح",
  saveError: "فشل في حفظ الإعدادات",
  loadError: "فشل في تحميل الإعدادات",
  backendUrlError: "رابط الخادم الخلفي غير صالح",
  noHistory: "لا توجد عمليات فحص حالية",
};

let loadedSettings = null;
let saveButtonDisabled = false;

const statusBadge = document.getElementById("statusBadge");
const statusText = document.getElementById("statusText");
const useBackendToggle = document.getElementById("useBackendToggle");
const backendUrlInput = document.getElementById("backendUrlInput");
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

function sendMessage(msg) {
  try {
    if (!chrome || !chrome.runtime || typeof chrome.runtime.sendMessage !== "function") {
      return { ok: false, error: "runtime unavailable" };
    }
    const response = chrome.runtime.sendMessage(msg);
    // Though not always async here, just in case; but spec says sendMessage is sync-like in some cases - we just need to check
    if (response && typeof response.then === "function") {
      // If it returns a promise, handle with callback style not needed; but better to handle
      // For this simple case, we'll use a callback approach via runtime
    }
  } catch (e) {
    return { ok: false, error: e?.message || String(e) };
  }

  // Try with callback for async responses
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (resp) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message || String(chrome.runtime.lastError) });
          return;
        }
        if (!resp || typeof resp !== "object") {
          resolve({ ok: false, error: "invalid response" });
          return;
        }
        resolve(resp);
      });
    } catch (e) {
      resolve({ ok: false, error: e?.message || String(e) });
    }
  });
}

function isValidBackendUrl(url) {
  if (typeof url !== "string") {
    return false;
  }
  const trimmed = url.trim();
  if (trimmed === "") {
    return true;
  }
  if (trimmed.startsWith("https://")) {
    return true;
  }
  if (trimmed.startsWith("http://localhost")) {
    return true;
  }
  if (trimmed.startsWith("http://127.0.0.1")) {
    return true;
  }
  return false;
}

function populateForm(settings) {
  if (!settings || typeof settings !== "object") {
    return;
  }
  loadedSettings = settings;
  useBackendToggle.checked = !!settings.useBackend;
  backendUrlInput.value = typeof settings.backendUrl === "string" ? settings.backendUrl : "";
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
  const li = document.createElement("li");
  li.classList.add("log-item");
  
  const left = document.createElement("div");
  const filename = document.createElement("div");
  filename.textContent = entry && typeof entry.filename === "string" ? entry.filename : "";
  const meta = document.createElement("div");
  const parts = [];
  if (entry && typeof entry.host === "string") {
    parts.push(entry.host);
  }
  if (entry && typeof entry.score === "number") {
    parts.push("score:" + entry.score);
  }
  if (entry && entry.timestamp) {
    try {
      parts.push(new Date(entry.timestamp).toLocaleString());
    } catch (e) {
      // ignore
    }
  }
  meta.textContent = parts.join(" | ");
  left.appendChild(filename);
  left.appendChild(meta);
  
  const right = document.createElement("div");
  if (entry && typeof entry.verdict === "string") {
    const v = entry.verdict;
    const badge = document.createElement("span");
    badge.classList.add("verdict-badge");
    if (v === "safe") {
      badge.classList.add("verdict-safe");
      badge.textContent = "آمن";
    } else if (v === "suspicious") {
      badge.classList.add("verdict-suspicious");
      badge.textContent = "مشكوك";
    } else if (v === "dangerous") {
      badge.classList.add("verdict-dangerous");
      badge.textContent = "خطير";
    } else {
      badge.textContent = v;
    }
    right.appendChild(badge);
  }
  li.appendChild(left);
  li.appendChild(right);
  return li;
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
  if (resp && resp.ok && Array.isArray(resp.history)) {
    if (resp.history.length === 0) {
      const empty = document.createElement("li");
      empty.classList.add("log-item", "empty");
      empty.textContent = STRINGS.noHistory;
      logsList.appendChild(empty);
    } else {
      const max = resp.history.length;
      for (let i = 0; i < max; i++) {
        logsList.appendChild(createLogItem(resp.history[i]));
      }
    }
  } else {
    const empty = document.createElement("li");
    empty.classList.add("log-item", "empty");
    empty.textContent = STRINGS.noHistory;
    logsList.appendChild(empty);
  }
}

async function saveSettings() {
  const settings = {
    ...(loadedSettings || {}),
  };
  settings.useBackend = !!useBackendToggle.checked;
  settings.backendUrl = backendUrlInput.value;
  const sens = sensitivitySelect.value;
  if (sens === "low" || sens === "medium" || sens === "high") {
    settings.sensitivity = sens;
  }
  settings.enabled = !!enabledToggle.checked;
  
  if (!isValidBackendUrl(settings.backendUrl)) {
    setMessage(STRINGS.backendUrlError, "error");
    return;
  }
  
  setMessage("", null);
  const resp = await sendMessage({ type: "SET_SETTINGS", settings });
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
  saveSettings();
});

clearHistoryBtn.addEventListener("click", () => {
  clearHistory();
});

enabledToggle.addEventListener("change", () => {
  setStatus(enabledToggle.checked);
});

document.addEventListener("DOMContentLoaded", () => {
  loadSettings();
  loadHistory();
});

if (chrome && chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local") {
      if (changes.history || changes.settings) {
        loadHistory();
        if (changes.settings) {
          loadSettings();
        }
      }
    }
  });
}
