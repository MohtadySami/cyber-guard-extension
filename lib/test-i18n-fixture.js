// Shared test fixture: loads the REAL _locales catalogues into lib/i18n.js so
// tests assert against the translations that actually ship, not fixtures.
import { readFileSync } from "node:fs";
import { registerCatalogue, resetCatalogues } from "./i18n.js";

/**
 * Registers every shipped catalogue for the given root directory.
 *
 * @param {string} [root] - Extension root containing _locales/.
 * @returns {Record<string, object>} The loaded catalogues keyed by language.
 */
export function loadRealCatalogues(root = new URL("../_locales/", import.meta.url)) {
  resetCatalogues();
  const base = root.pathname.replace(/^\/([A-Za-z]:)/u, "$1");
  const catalogues = {};
  for (const lang of ["en", "ar", "es", "fr"]) {
    const file = `${base}${lang}/messages.json`;
    catalogues[lang] = JSON.parse(readFileSync(file, "utf8"));
    registerCatalogue(lang, catalogues[lang]);
  }
  return catalogues;
}
