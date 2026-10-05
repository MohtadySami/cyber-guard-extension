// Localization layer for Cyber Guard.
//
// HYBRID DESIGN (see PROJECT_REPORT.md §Localization):
//
//   * `_locales/<lang>/messages.json` is the single source of truth for every
//     user-facing string. The files are valid Chrome i18n catalogues, so the
//     manifest can reference them with `__MSG_*__` and `chrome.i18n.getMessage()`
//     serves the Chrome-controlled surfaces (store listing, browser UI).
//
//   * `chrome.i18n.getMessage()` resolves against the BROWSER UI locale and has
//     no API for requesting a specific language (crbug/660704). That makes it
//     unusable for Cyber Guard's runtime language selector. So this module
//     resolves the same catalogues itself, reading the user's stored preference
//     and passing the language in explicitly.
//
// The public API is unchanged from 0.1.x (t, normalizeLanguage, getDirection,
// getLocale, localizeReason, getNotificationButtons), so every call site and
// every existing test keeps working. The only behavioural change is that the
// default language is now "en" instead of "ar".

/** Languages shipped in this release. */
export const SUPPORTED_LANGUAGES = Object.freeze(["en", "ar", "es", "fr"]);

/** English is the default for new installs (0.2.0). */
export const DEFAULT_LANGUAGE = "en";

/** Locale used for date/number formatting, per language. */
const LOCALES = Object.freeze({
  en: "en-US",
  ar: "ar-EG",
  es: "es-ES",
  fr: "fr-FR",
});

/** Text direction per language. Arabic is the only RTL language here. */
const DIRECTIONS = Object.freeze({
  en: "ltr",
  ar: "rtl",
  es: "ltr",
  fr: "ltr",
});

/** Native names shown in the language selector, in their own language. */
const LANGUAGE_NAMES = Object.freeze({
  en: "languageOptionEn",
  ar: "languageOptionAr",
  es: "languageOptionEs",
  fr: "languageOptionFr",
});

/**
 * Stable heuristic code -> catalogue key. Reasons are localized by CODE so the
 * underlying scoring data stays language-independent.
 */
export const REASON_MESSAGE_KEYS = Object.freeze({
  SCRIPT_EXTENSION: "reasonScriptExtension",
  EXECUTABLE_EXTENSION: "reasonExecutableExtension",
  CONTAINER_EXTENSION: "reasonContainerExtension",
  MACRO_DOCUMENT: "reasonMacroDocument",
  DOUBLE_EXTENSION: "reasonDoubleExtension",
  RTLO_CHARACTER: "reasonRtloCharacter",
  TRAILING_SPACES_OR_DOTS: "reasonTrailingSpacesOrDots",
  MIME_MISMATCH: "reasonMimeMismatch",
  INSECURE_HTTP: "reasonInsecureHttp",
  IP_HOST: "reasonIpHost",
  SUSPICIOUS_TLD: "reasonSuspiciousTld",
  PUNYCODE_HOST: "reasonPunycodeHost",
  LONG_REDIRECT_CHAIN: "reasonLongRedirectChain",
  TRUSTED_DOMAIN: "reasonTrustedDomain",
});

/** Stable verdict value -> catalogue key. */
export const VERDICT_MESSAGE_KEYS = Object.freeze({
  safe: "verdictSafe",
  suspicious: "verdictSuspicious",
  dangerous: "verdictDangerous",
});

/** Stable decision value -> catalogue key. */
export const DECISION_MESSAGE_KEYS = Object.freeze({
  allow: "decisionAllow",
  cancel: "decisionCancel",
  delete: "decisionDelete",
  keep: "decisionKeep",
});

/**
 * Loaded catalogues, keyed by language. A catalogue is the parsed
 * `_locales/<lang>/messages.json` object: { key: {message, placeholders?} }.
 * @type {Map<string, Record<string, {message: string, placeholders?: object}>>}
 */
const catalogues = new Map();

/**
 * Registers a parsed catalogue for a language.
 *
 * Kept separate from loading so tests can inject catalogues synchronously and
 * so the module stays usable in Node without any fetch.
 *
 * @param {string} language - Language code.
 * @param {Record<string, object>} messages - Parsed messages.json content.
 * @returns {boolean} True when the catalogue was accepted.
 */
export function registerCatalogue(language, messages) {
  if (
    typeof language !== "string" ||
    !SUPPORTED_LANGUAGES.includes(language) ||
    !messages ||
    typeof messages !== "object"
  ) {
    return false;
  }
  catalogues.set(language, messages);
  return true;
}

/**
 * Loads a catalogue from `_locales/<lang>/messages.json`.
 *
 * Uses an injected loader so this module never touches `fetch` or `chrome.*`
 * itself. The caller supplies the transport (extension page: fetch of
 * chrome.runtime.getURL; tests: a fixture).
 *
 * @param {string} language - Language code to load.
 * @param {(url: string) => Promise<object>} loader - Async catalogue loader.
 * @returns {Promise<boolean>} True when the catalogue is available afterwards.
 */
export async function loadCatalogue(language, loader) {
  const lang = normalizeLanguage(language);
  if (catalogues.has(lang) || typeof loader !== "function") {
    return catalogues.has(lang);
  }
  try {
    const messages = await loader(`_locales/${lang}/messages.json`);
    return registerCatalogue(lang, messages);
  } catch {
    // A missing catalogue must never break the UI; t() falls back to the key.
    return false;
  }
}

/** Clears every registered catalogue. Test-only helper. */
export function resetCatalogues() {
  catalogues.clear();
}

/** @returns {boolean} True when a catalogue is loaded for this language. */
export function hasCatalogue(language) {
  return catalogues.has(normalizeLanguage(language));
}

/**
 * Normalizes any stored/user-supplied language value.
 * Anything malformed or unsupported resolves to English.
 *
 * @param {unknown} language - Candidate language code.
 * @returns {string} A supported language code.
 */
export function normalizeLanguage(language) {
  if (typeof language !== "string") {
    return DEFAULT_LANGUAGE;
  }
  const candidate = language.trim().toLowerCase();
  if (SUPPORTED_LANGUAGES.includes(candidate)) {
    return candidate;
  }
  // Tolerate regional tags such as "en-US" / "fr_CA".
  const base = candidate.split(/[-_]/)[0];
  if (SUPPORTED_LANGUAGES.includes(base)) {
    return base;
  }
  return DEFAULT_LANGUAGE;
}

/**
 * Substitutes $NAME$ tokens using a Chrome-style placeholder map and an array of
 * positional values ($1, $2, ...), matching chrome.i18n semantics.
 *
 * @param {string} template - Message text containing $NAME$ tokens.
 * @param {Record<string, {content: string}>} [placeholders] - Placeholder map.
 * @param {unknown[]} [params] - Positional values.
 * @returns {string} The interpolated string.
 */
function interpolate(template, placeholders, params) {
  if (!placeholders || !Array.isArray(params)) {
    return template;
  }
  return template.replace(/\$([A-Z][A-Z0-9_]*)\$/gu, (token, name) => {
    const entry = placeholders[name];
    if (!entry || typeof entry.content !== "string") {
      return token;
    }
    const index = Number.parseInt(entry.content.replace("$", ""), 10);
    if (!Number.isInteger(index) || index < 1 || index > params.length) {
      return token;
    }
    const value = params[index - 1];
    return value === undefined || value === null ? token : String(value);
  });
}

/**
 * Resolves $NAME$ tokens against a NAMED value object.
 *
 * Heuristic reasons carry named params ({filename, extension, hostname, ...}), so
 * resolving by name keeps the catalogue's placeholder indices irrelevant. That
 * removes the need for a second, hand-maintained ordering list that could drift
 * out of sync with the message files.
 *
 * @param {string} template - Message text containing $NAME$ tokens.
 * @param {Record<string, {content: string}>} [placeholders] - Placeholder map.
 * @param {Record<string, unknown>} [named] - Named values, case-insensitive keys.
 * @returns {string} The interpolated string.
 */
function interpolateNamed(template, placeholders, named) {
  if (!placeholders || !named || typeof named !== "object") {
    return template;
  }
  const lowered = new Map();
  for (const [key, value] of Object.entries(named)) {
    lowered.set(key.toLowerCase(), value);
  }
  return template.replace(/\$([A-Z][A-Z0-9_]*)\$/gu, (token, name) => {
    if (!Object.hasOwn(placeholders, name)) {
      return token;
    }
    const value = lowered.get(name.toLowerCase());
    return value === undefined || value === null ? token : String(value);
  });
}

/**
 * Translates a key using named values instead of positional ones.
 *
 * @param {string} key - Message key.
 * @param {string} language - Target language.
 * @param {Record<string, unknown>} named - Named placeholder values.
 * @returns {string} The translated string.
 */
function tNamed(key, language, named) {
  if (typeof key !== "string" || !key) {
    return "";
  }
  const entry = lookup(key, normalizeLanguage(language));
  if (!entry || typeof entry.message !== "string") {
    return key;
  }
  return interpolateNamed(entry.message, entry.placeholders, named);
}

/**
 * Looks up a raw message entry, resolving language -> default -> miss.
 *
 * @param {string} key - Message key.
 * @param {string} language - Normalized language.
 * @returns {{message: string, placeholders?: object}|null}
 */
function lookup(key, language) {
  const own = catalogues.get(language);
  if (own && Object.hasOwn(own, key)) {
    return own[key];
  }
  const fallback = catalogues.get(DEFAULT_LANGUAGE);
  if (fallback && Object.hasOwn(fallback, key)) {
    return fallback[key];
  }
  return null;
}

/**
 * Translates a key for a language.
 *
 * Resolution order: requested language -> English -> the key itself, so a
 * missing translation degrades to something visible instead of blank UI.
 *
 * @param {string} key - Stable message key.
 * @param {string} [language] - Target language; normalized internally.
 * @param {unknown[]} [params] - Positional placeholder values.
 * @returns {string} The translated string.
 */
export function t(key, language, params) {
  if (typeof key !== "string" || !key) {
    return "";
  }
  const entry = lookup(key, normalizeLanguage(language));
  if (!entry || typeof entry.message !== "string") {
    return key;
  }
  return interpolate(entry.message, entry.placeholders, params);
}

/**
 * @param {string} [language] - Target language.
 * @returns {string} "rtl" for Arabic, "ltr" otherwise.
 */
export function getDirection(language) {
  return DIRECTIONS[normalizeLanguage(language)];
}

/**
 * @param {string} [language] - Target language.
 * @returns {string} A BCP-47 locale usable with toLocaleString().
 */
export function getLocale(language) {
  return LOCALES[normalizeLanguage(language)];
}

/**
 * Native display name for a language, shown in the language selector.
 *
 * @param {string} language - Language code.
 * @returns {string} The localized name of that language.
 */
export function getLanguageName(language) {
  const key = LANGUAGE_NAMES[normalizeLanguage(language)];
  return t(key, language);
}

/**
 * Localizes a heuristic reason by its stable code.
 *
 * The reason's own `text` is used only as a last resort: an unknown code, or a
 * code with no catalogue entry, falls back to it so no notification line goes
 * blank.
 *
 * @param {{code?: string, text?: string, params?: Record<string, unknown>}} reason
 * @param {string} [language] - Target language.
 * @returns {string} The localized reason sentence.
 */
export function localizeReason(reason, language) {
  if (!reason || typeof reason !== "object") {
    return "";
  }
  const code = typeof reason.code === "string" ? reason.code : "";
  const key = code ? REASON_MESSAGE_KEYS[code] : undefined;
  if (key) {
    // Resolved by param NAME, so the catalogue's placeholder indices stay an
    // implementation detail of the message file.
    const rendered = tNamed(key, language, reason.params);
    if (rendered !== key) {
      return rendered;
    }
  }
  return typeof reason.text === "string" ? reason.text : "";
}

/**
 * Localized label for a stored verdict value.
 *
 * @param {string} verdict - Canonical verdict: safe | suspicious | dangerous.
 * @param {string} [language] - Target language.
 * @returns {string} The localized label, or "" for an unknown verdict.
 */
export function getVerdictLabel(verdict, language) {
  const key = typeof verdict === "string" ? VERDICT_MESSAGE_KEYS[verdict] : undefined;
  return key ? t(key, language) : "";
}

/**
 * Localized label for a stored decision value.
 *
 * @param {string} decision - Canonical decision: allow | cancel | delete | keep.
 * @param {string} [language] - Target language.
 * @returns {string} The localized label, or "" for an unknown decision.
 */
export function getDecisionLabel(decision, language) {
  const key = typeof decision === "string" ? DECISION_MESSAGE_KEYS[decision] : undefined;
  return key ? t(key, language) : "";
}

/**
 * Localized labels for the two notification button slots.
 * Index 0 is always the destructive action (cancel / delete), index 1 the
 * permissive one (allow / keep) — resolveDecision() depends on that order.
 *
 * @param {"held"|"completed"} kind - Which notification is being built.
 * @param {string} [language] - Target language.
 * @returns {{cancel: string, allow: string, delete: string, keep: string}}
 */
export function getNotificationButtonLabels(kind, language) {
  void kind;
  return {
    cancel: t("btnCancelDownload", language),
    allow: t("btnAllowAnyway", language),
    delete: t("btnDeleteFile", language),
    keep: t("btnKeepFile", language),
  };
}

/**
 * Ordered button titles for a notification, matching Chrome's button index
 * contract: 0 = cancel/delete, 1 = allow/keep.
 *
 * @param {"held"|"completed"} kind - "held" or "completed".
 * @param {string} [language] - Target language.
 * @returns {string[]} Exactly two button titles.
 */
export function getNotificationButtons(kind, language) {
  const labels = getNotificationButtonLabels(kind, language);
  return kind === "completed" ? [labels.delete, labels.keep] : [labels.cancel, labels.allow];
}
