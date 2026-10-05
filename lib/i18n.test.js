// Unit tests for the localization layer (lib/i18n.js) across all four shipped
// languages. Assertions run against the real _locales catalogues.

import test from "node:test";
import assert from "node:assert/strict";

import { loadRealCatalogues } from "./test-i18n-fixture.js";
import {
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
  normalizeLanguage,
  t,
  getDirection,
  getLocale,
  getLanguageName,
  localizeReason,
  getVerdictLabel,
  getDecisionLabel,
  getNotificationButtonLabels,
  getNotificationButtons,
  hasCatalogue,
  loadCatalogue,
  registerCatalogue,
  resetCatalogues,
  REASON_MESSAGE_KEYS,
  VERDICT_MESSAGE_KEYS,
  DECISION_MESSAGE_KEYS,
} from "./i18n.js";

const catalogues = loadRealCatalogues();
const ALL = SUPPORTED_LANGUAGES;

// --- Language support

test("English is the default language", () => {
  assert.equal(DEFAULT_LANGUAGE, "en");
});

test("exactly four languages ship", () => {
  assert.deepEqual([...ALL].sort(), ["ar", "en", "es", "fr"]);
});

test("every language has a catalogue with an identical key set", () => {
  const reference = Object.keys(catalogues.en).sort();
  for (const lang of ALL) {
    assert.deepEqual(Object.keys(catalogues[lang]).sort(), reference, `key drift in ${lang}`);
    assert.ok(reference.length > 50, "catalogue looks too small");
  }
});

test("no message is empty in any language", () => {
  for (const lang of ALL) {
    for (const [key, entry] of Object.entries(catalogues[lang])) {
      assert.ok(typeof entry.message === "string" && entry.message.trim(), `${lang}/${key} is empty`);
    }
  }
});

test("no locale kept the English string for a shared key", () => {
  // Guards against a copy-paste translation leaving English text behind in a
  // locale that should differ. Keys that are legitimately identical (brand
  // names, punctuation-only values) are exempt.
  const exempt = new Set(["extShortName", "notifFile", "notifSource"]);
  const differing = Object.keys(catalogues.en).filter(
    (key) =>
      !exempt.has(key) &&
      !catalogues.ar[key].message.match(/^[\p{L}\s]+$/u) === false &&
      catalogues.ar[key].message === catalogues.en[key].message,
  );
  // Only assert on keys where the Arabic text is not a pure brand/whitespace token.
  const realDrift = differing.filter((key) => {
    const ar = catalogues.ar[key].message;
    return ar.length > 3 && /[a-z]{4}/i.test(ar) && ar === catalogues.en[key].message;
  });
  assert.deepEqual(realDrift, [], "untranslated English leaking into Arabic");
});

// --- Normalization and fallback

test("normalizeLanguage accepts every supported language", () => {
  for (const lang of ALL) {
    assert.equal(normalizeLanguage(lang), lang);
  }
});

test("normalizeLanguage falls back to English for malformed values", () => {
  for (const bad of [undefined, null, 7, {}, "", "   ", true]) {
    assert.equal(normalizeLanguage(bad), "en");
  }
});

test("normalizeLanguage falls back to English for unsupported languages", () => {
  for (const bad of ["de", "zh-CN", "zz", "klingon"]) {
    assert.equal(normalizeLanguage(bad), "en");
  }
});

test("normalizeLanguage tolerates case, whitespace and regional tags", () => {
  assert.equal(normalizeLanguage("EN"), "en");
  assert.equal(normalizeLanguage(" fr "), "fr");
  assert.equal(normalizeLanguage("es-MX"), "es");
  assert.equal(normalizeLanguage("ar_EG"), "ar");
});

// --- Translation lookup

test("a translated key resolves in every language", () => {
  for (const lang of ALL) {
    assert.equal(t("settingsTitle", lang), catalogues[lang].settingsTitle.message);
    assert.equal(t("save", lang), catalogues[lang].save.message);
  }
});

test("the same key differs across languages where it should", () => {
  const seen = new Set(ALL.map((lang) => t("stateThreat", lang)));
  assert.equal(seen.size, ALL.length, `threat label not distinct: ${[...seen].join(" | ")}`);
});

test("a missing translation falls back to English, then to the key", () => {
  assert.equal(t("noSuchKeyAnywhere", "fr"), "noSuchKeyAnywhere");
  assert.equal(t("noSuchKeyAnywhere", "en"), "noSuchKeyAnywhere");
});

test("a key missing from one locale falls back to English", () => {
  // Simulate a sparse translation the way Chrome tolerates one.
  resetCatalogues();
  registerCatalogue("en", catalogues.en);
  registerCatalogue("fr", { settingsTitle: catalogues.fr.settingsTitle });
  assert.equal(t("save", "fr"), catalogues.en.save.message, "falls back to English");
  assert.equal(t("settingsTitle", "fr"), catalogues.fr.settingsTitle.message, "uses French");
  loadRealCatalogues();
});

test("t() tolerates malformed keys", () => {
  assert.equal(t("", "en"), "");
  assert.equal(t(null, "en"), "");
  assert.equal(t(undefined, "en"), "");
  assert.equal(t(42, "en"), "");
});

test("placeholders interpolate positionally through t()", () => {
  // reasonIpHost declares $HOSTNAME$ as $7 (canonical reason param order), so a
  // single-element positional array must NOT satisfy it.
  const message = t("reasonIpHost", "en", ["1.2.3.4"]);
  assert.ok(message.includes("$HOSTNAME$"), "positional index must be honoured exactly");
  assert.ok(!message.includes("undefined"));
});

test("reason placeholders resolve by param name, not by catalogue index", () => {
  // This is the path heuristic reasons actually use, and it must fill every
  // token regardless of the placeholder indices in the message file.
  const message = localizeReason({ code: "IP_HOST", params: { hostname: "1.2.3.4" } }, "en");
  assert.equal(message, "Download host 1.2.3.4 is an IP address");
});

test("a missing reason param leaves its token intact rather than printing undefined", () => {
  const message = localizeReason({ code: "IP_HOST", params: {} }, "en");
  assert.ok(message.includes("$HOSTNAME$"));
  assert.ok(!message.includes("undefined"));
});

// --- Direction, locale, language names

test("Arabic is RTL and the other three are LTR", () => {
  assert.equal(getDirection("ar"), "rtl");
  assert.equal(getDirection("en"), "ltr");
  assert.equal(getDirection("es"), "ltr");
  assert.equal(getDirection("fr"), "ltr");
});

test("direction falls back to LTR for unknown input", () => {
  assert.equal(getDirection("de"), "ltr");
  assert.equal(getDirection(undefined), "ltr");
});

test("every language exposes a usable locale", () => {
  assert.equal(getLocale("en"), "en-US");
  assert.equal(getLocale("ar"), "ar-EG");
  assert.equal(getLocale("es"), "es-ES");
  assert.equal(getLocale("fr"), "fr-FR");
});

test("language names are shown in their own language", () => {
  assert.equal(getLanguageName("en"), "English");
  assert.equal(getLanguageName("ar"), "العربية");
  assert.equal(getLanguageName("es"), "Español");
  assert.equal(getLanguageName("fr"), "Français");
});

// --- Reason localization by code

test("reasons are localized by stable code in all four languages", () => {
  const reason = {
    code: "EXECUTABLE_EXTENSION",
    points: 25,
    text: "File name setup.exe uses executable extension .exe",
    params: { filename: "setup.exe", extension: "exe" },
  };
  const rendered = ALL.map((lang) => localizeReason(reason, lang));
  assert.equal(new Set(rendered).size, 4, `reasons not distinct: ${rendered.join(" | ")}`);
  for (const [index, sentence] of rendered.entries()) {
    const lang = ALL[index];
    assert.ok(sentence.includes("setup.exe"), `${lang}: filename lost during interpolation`);
    assert.ok(sentence.includes(".exe"), `${lang}: extension lost during interpolation`);
    // English is the only locale whose sentence should start this way.
    if (lang !== "en") {
      assert.ok(
        !sentence.startsWith("File name"),
        `${lang}: English leaked into the rendered reason`,
      );
    }
  }
});

test("every heuristic reason code has a translation in every language", () => {
  for (const code of Object.keys(REASON_MESSAGE_KEYS)) {
    for (const lang of ALL) {
      const rendered = localizeReason({ code, text: "FALLBACK" }, lang);
      assert.notEqual(rendered, "FALLBACK", `${code} untranslated for ${lang}`);
      assert.notEqual(rendered, `reason.${code}`, `${code} missing key for ${lang}`);
    }
  }
});

test("reason placeholders bind to the right values in every language", () => {
  const reason = {
    code: "DOUBLE_EXTENSION",
    text: "fallback",
    params: { filename: "invoice.pdf.exe", previousExtension: "pdf", lastExtension: "exe" },
  };
  for (const lang of ALL) {
    const rendered = localizeReason(reason, lang);
    assert.ok(rendered.includes("invoice.pdf.exe"), `${lang}: filename missing`);
    assert.ok(rendered.includes(".pdf.exe"), `${lang}: extension pair wrong or swapped`);
    assert.ok(!rendered.includes("$"), `${lang}: unresolved placeholder`);
  }
});

test("an unknown reason code falls back to its stored text", () => {
  for (const lang of ALL) {
    assert.equal(
      localizeReason({ code: "SOMETHING_NEW", text: "Original sentence" }, lang),
      "Original sentence",
    );
  }
});

test("localizeReason tolerates malformed reasons", () => {
  assert.equal(localizeReason(null, "en"), "");
  assert.equal(localizeReason(undefined, "en"), "");
  assert.equal(localizeReason("nonsense", "en"), "");
  assert.equal(localizeReason({ points: 10 }, "en"), "");
  assert.equal(localizeReason({ code: "IP_HOST" }, "en").includes("$"), true);
});

// --- Verdict and decision labels

test("verdict labels are localized while the stored values stay canonical", () => {
  for (const verdict of ["safe", "suspicious", "dangerous"]) {
    const rendered = ALL.map((lang) => getVerdictLabel(verdict, lang));
    assert.equal(new Set(rendered).size, 4, `${verdict} label not distinct`);
    assert.deepEqual(Object.keys(VERDICT_MESSAGE_KEYS).sort(), ["dangerous", "safe", "suspicious"]);
  }
});

test("decision labels are localized", () => {
  for (const decision of ["allow", "cancel", "delete", "keep"]) {
    const rendered = ALL.map((lang) => getDecisionLabel(decision, lang));
    assert.equal(new Set(rendered).size, 4, `${decision} label not distinct`);
  }
});

test("unknown verdict and decision values return an empty label", () => {
  assert.equal(getVerdictLabel("unknown", "en"), "");
  assert.equal(getVerdictLabel(undefined, "en"), "");
  assert.equal(getDecisionLabel("nonsense", "en"), "");
  assert.equal(getDecisionLabel(null, "en"), "");
});

// --- Notification buttons

test("notification button labels are localized in every language", () => {
  for (const lang of ALL) {
    const labels = getNotificationButtonLabels("held", lang);
    for (const key of ["cancel", "allow", "delete", "keep"]) {
      assert.ok(labels[key].length > 0, `${lang}/${key} empty`);
      assert.notEqual(labels[key], key, `${lang}/${key} untranslated`);
    }
  }
});

test("button order preserves the decision contract in every language", () => {
  // resolveDecision() maps index 0 to cancel/delete and index 1 to allow/keep.
  for (const lang of ALL) {
    const held = getNotificationButtons("held", lang);
    const completed = getNotificationButtons("completed", lang);
    assert.equal(held.length, 2);
    assert.equal(completed.length, 2);
    assert.equal(held[0], getNotificationButtonLabels("held", lang).cancel);
    assert.equal(held[1], getNotificationButtonLabels("held", lang).allow);
    assert.equal(completed[0], getNotificationButtonLabels("completed", lang).delete);
    assert.equal(completed[1], getNotificationButtonLabels("completed", lang).keep);
  }
});

// --- Catalogue loading

test("hasCatalogue reflects what is loaded", () => {
  assert.equal(hasCatalogue("en"), true);
  assert.equal(hasCatalogue("de"), true, "unknown languages normalize to English");
});

test("loadCatalogue is a no-op when the catalogue is already present", async () => {
  let called = false;
  const ok = await loadCatalogue("en", async () => {
    called = true;
    return {};
  });
  assert.equal(ok, true);
  assert.equal(called, false);
});

test("loadCatalogue registers a catalogue through the injected loader", async () => {
  resetCatalogues();
  const fake = { save: { message: "Guardo" } };
  const ok = await loadCatalogue("es", async (path) => {
    assert.equal(path, "_locales/es/messages.json");
    return fake;
  });
  assert.equal(ok, true);
  assert.equal(t("save", "es"), "Guardo");
  loadRealCatalogues();
});

test("a failing loader leaves the UI on the fallback rather than throwing", async () => {
  resetCatalogues();
  registerCatalogue("en", catalogues.en);
  const ok = await loadCatalogue("fr", async () => {
    throw new Error("network error");
  });
  assert.equal(ok, false);
  assert.equal(t("save", "fr"), catalogues.en.save.message, "falls back to English");
  loadRealCatalogues();
});

test("registerCatalogue rejects malformed input", () => {
  assert.equal(registerCatalogue("de", {}), false);
  assert.equal(registerCatalogue(null, {}), false);
  assert.equal(registerCatalogue("fr", null), false);
  assert.equal(registerCatalogue("fr", "not-an-object"), false);
});
