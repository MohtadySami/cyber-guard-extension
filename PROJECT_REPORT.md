# Cyber Guard — Technical Report

**Version:** 0.2.0
**Status:** pre-release academic prototype. Not published to the Chrome Web Store.
**Name:** Cyber Guard: Download Security Assistant
**Last verified commit:** `2564bb9`

> **Scope.** Cyber Guard is a download-monitoring browser extension. It is **not** an antivirus, a
> content scanner, a hash scanner, a reputation service, or an execution monitor. It performs
> local heuristic analysis of the file **name**, **source URL**, and **MIME type** only.

---

## 1. Architecture

```
manifest.json           MV3 manifest, 4 required permissions, 2 optional permissions
background.js           service worker: settings, download lifecycle, decisions,
                        notifications, alarms, recovery, message API
popup.html / .css / .js the popup UI (RTL-capable)

lib/heuristics.js       pure detectors → {code, points, text, params}
lib/scoring.js          score + verdict from reasons and sensitivity thresholds
lib/alert.js            notification text builders (presentation only)
lib/i18n.js             localization resolver over _locales catalogues
lib/page-alert.js       one-shot page threat alert: gating, payload, injected renderer
lib/threat/provider.js  threat-intelligence provider interface (null + local only)
lib/threat/engine.js    threat-state machine; provider can never change a verdict
lib/history.js          persistent local decision history
lib/popup-core.js       DOM-free popup view models and messaging
_locales/{en,ar,es,fr}/messages.json   69 user-facing keys × 4 languages
lib/*.test.js           node:test suites (285 tests total)
```

Analysis is entirely local. There is **no** `XMLHttpRequest`, **no** `WebSocket`, **no**
registered content script, and **no** backend. The two `fetch()` calls in the codebase read
Cyber Guard's own packaged `_locales/*.json` via `chrome.runtime.getURL()`; nothing is requested
from the network.

Two permissions are **optional** and granted only if the user enables page alerts: `scripting`
and host access limited to `http://*/*` + `https://*/*`. `<all_urls>` is never requested and no
required permission was added in 0.2.0.

### Module rules

`lib/heuristics.js`, `lib/scoring.js`, `lib/i18n.js`, `lib/alert.js`, `lib/page-alert.js`,
`lib/popup-core.js`, `lib/threat/engine.js`, and `lib/threat/provider.js` are free of `chrome.*`
at module scope so they run unchanged in Chrome and under `node --test`. Only `background.js`,
`popup.js`, and `lib/history.js` touch Chrome APIs.

---

## 2. Detection and scoring

### Heuristic signals

All values below are extracted directly from `lib/heuristics.js` (`HEURISTIC_CONSTANTS`) and
`lib/scoring.js` (`SCORING_CONSTANTS`).

**13 active signals. 1 stub (always returns null).**

| Code | Points | Category | Notes |
|---|---:|---|---|
| `RTLO_CHARACTER` | 50 | Filename | **hard signal** — bidi-control char in filename (U+202A–U+202E, U+2066–U+2069) |
| `DOUBLE_EXTENSION` | 40 | Filename | **hard signal** — document/media ext followed by script/exe ext |
| `SCRIPT_EXTENSION` | 35 | Filename | 15 script extensions: `ps1 vbs vbe js jse hta wsf wsh bat cmd lnk reg scr pif msc` |
| `MIME_MISMATCH` | 30 | Content-type | **hard signal** — document/media ext + executable MIME type |
| `EXECUTABLE_EXTENSION` | 25 | Filename | 9 extensions: `exe msi dll jar com cpl msp appx msix` |
| `TRAILING_SPACES_OR_DOTS` | 20 | Filename | Spaces before ext, repeated dots before ext, or 5+ consecutive spaces |
| `IP_HOST` | 20 | Host | IPv4 or IPv6 literal host |
| `MACRO_DOCUMENT` | 15 | Filename | 5 extensions: `docm xlsm pptm dotm xlam` |
| `PUNYCODE_HOST` | 15 | Host | Any host label starts with `xn--` |
| `CONTAINER_EXTENSION` | 10 | Filename | 8 extensions: `iso img vhd vhdx zip rar 7z cab` |
| `INSECURE_HTTP` | 10 | URL | Download URL uses `http:` |
| `SUSPICIOUS_TLD` | 10 | Host | 13 TLDs: `zip mov xyz top click work rest country gq tk ml cf ga` |
| `LONG_REDIRECT_CHAIN` | 10 / 20 | URL | ≥3 hops (10 pts) or ≥5 hops (20 pts) — **never fires in production** (see §7) |
| `LOOKALIKE_DOMAIN` | — | Host | **Stub** — always returns null; not yet implemented |

**Hard signals** (`RTLO_CHARACTER`, `DOUBLE_EXTENSION`, `MIME_MISMATCH`) count even when the
source host is on the user's trusted-domain list. All other signals are suppressed for trusted hosts.

### Score formula

```
score = clamp( Σ points(reason_i), 0, 100 )
```

Points from each triggered signal are summed. The total is clamped to `[0, 100]` and truncated to
an integer. A trusted-domain bypass (when no hard signal is present) sets `score = 0` directly.

### Verdict thresholds

Directly from `SCORING_CONSTANTS.THRESHOLDS` in `lib/scoring.js`:

| Sensitivity | Suspicious ≥ | Dangerous ≥ |
|---|---:|---:|
| low | 40 | 70 |
| medium *(default)* | 30 | 60 |
| high | 20 | 50 |

These values are **not** affected by the interface language, history, or any runtime state.

### Reason objects

```js
{
  code: "DOUBLE_EXTENSION",              // stable identifier
  points: 40,                            // scoring input
  text: "File name invoice.pdf.exe ...", // canonical English sentence (fallback)
  params: { filename, previousExtension, lastExtension },  // language-independent data
}
```

`code` and `points` are the security contract. `text` is the canonical sentence retained for
storage and English-only consumers. `params` feeds localized rendering; it contains no display
strings. Reasons are localized at render time by `code`, never by translating stored text.

---

## 3. Localization (four languages)

### Supported languages

| Code | Language | Direction |
|---|---|---|
| `en` | English — default | `ltr` |
| `ar` | Arabic | `rtl` |
| `es` | Spanish | `ltr` |
| `fr` | French | `ltr` |

### Why a runtime resolver is required

`chrome.i18n.getMessage()` resolves against the **browser UI locale** and provides no API for
requesting a specific language — [crbug/660704](https://github.com/w3c/webextensions/issues/252)
is still open. A pure `chrome.i18n` implementation cannot honour a runtime language selector.

The design splits responsibilities:

| Concern | Mechanism |
|---|---|
| Manifest name / description, browser UI, store listing | Native `_locales` + `__MSG_*__` + `default_locale: "en"` |
| Popup, notifications, page alert | `lib/i18n.js` resolving the same catalogues at runtime |

`_locales/<lang>/messages.json` is the single source of truth: 69 keys per language, written as
valid Chrome catalogues, so both mechanisms read the same files.

### Resolver API

```
t(key, language, params)             requested → English → the key itself
normalizeLanguage(value)             any input → a supported code
getDirection / getLocale             RTL/LTR and date formatting
localizeReason(reason, language)     render a heuristic reason BY CODE
getVerdictLabel / getDecisionLabel   translate stored values at render time
getNotificationButtons(kind, lang)   ["Cancel","Allow"] | ["Delete","Keep"]
```

### Placeholders resolve by name

Reason sentences use Chrome-style `$NAME$` placeholders. Reasons carry **named** params
(`{filename, extension, hostname, …}`). Resolution is therefore by name against that object, so
the placeholder indices inside a message file are an implementation detail and cannot drift out of
sync with the scoring data.

### Persistence and fallback

- Language stored in `chrome.storage.local.settings.language`, default `"en"`.
- Pre-0.2.0 installs stored an explicit value — **their preference is preserved** with no migration.
- Malformed or unsupported values normalize to English. Regional tags (`en-US`, `fr_CA`) are accepted.

### Direction

`popup.js` is the only place that writes `lang`/`dir` and stamps `[data-i18n]` elements.
`popup.css` has no direction-specific rules; layout uses CSS logical properties.

### Security independence

Heuristics read no translation strings; scoring reads no locale. Stored history keeps canonical
values (`verdict: "dangerous"`, `decision: "cancel"`, `cause: "timeout"`) and is translated at
render time. Tests evaluate identical contexts in all four languages and assert identical scores
and verdicts.

---

## 4. Threat states and the threat engine

`lib/threat/engine.js` produces a normalized assessment:

```js
{
  state: "secure" | "analyzing" | "threat",
  finalVerdict: "safe" | "suspicious" | "dangerous",
  score,
  reasons,
  provider,
  providerAvailable
}
```

The crimson **THREAT** state requires `finalVerdict === "dangerous"`. A suspicious verdict uses
the secure-state radar and raises the ordinary suspicion notification — the visual state never
overstates the evidence.

### Provider abstraction (no external provider ships)

`lib/threat/provider.js` defines `async query(ctx) → normalizedResult` with canonical verdicts
`safe | suspicious | malicious | unavailable`. Bundled providers:

- `NullProvider` — always reports `unavailable` (the default when threat intel is disabled).
- `LocalProvider` — restates the local heuristic verdict (for testing the engine; ships but is not selected by `selectProvider()` in production).
- `HttpProvider` — **deliberately absent.**

**Invariant: a provider can never change a decision.** `finalVerdict` derives from the local
verdict alone. A `malicious` provider result cannot escalate a locally-safe download.
Every provider failure mode (unavailable, throwing, timeout at 1.5 s, malformed payload) normalizes
to `unavailable`, producing exactly the local-only assessment. Each case has a test.

**No VirusTotal integration.** Their public API prohibits use in commercial products/services
(500 req/day, 4 req/min, permanent ban for non-compliance); only the paid Private API allows it.
An embedded API key would be exposed to every user. Any future integration must use a backend
proxy holding the credential, with its own privacy disclosure. No file, URL or hash leaves the
browser in 0.2.0.

---

## 5. Page threat alert

On a confirmed verdict (safe, suspicious, or dangerous), Cyber Guard can show a warning directly
on the originating page with `chrome.scripting.executeScript({ world: "ISOLATED", func })`.
There is no registered content script.

**Privacy properties:**
- Closed shadow root — page CSS cannot restyle it; page JS cannot read it.
- `pointer-events: none` container — the page stays fully usable; no blocking overlay.
- Payload: verdict, file name, reason only — **no URL, no page content, no browsing history**.
- Accessibility: `role="alert"`, `aria-live="assertive"`, `dir`/`lang` for Arabic, reduced-motion guards.

**Permission required (optional, opt-in):** `scripting` + `http://*/*` + `https://*/*`.
`activeTab` is insufficient because a download is not a user gesture on the originating tab.
Without the permission, the alert is silently skipped.

---

## 6. Download protection flow

```
onCreated
  → settings check (enabled?)
  → pending session record (chrome.storage.session)
  → attempt pause
  → 2-second local analysis
  → re-query live download state
  → branch:
       safe            → resume
       risky, active   → hold + Cancel/Allow notification + 120 s alarm
       risky, complete → completed-risk notification + Delete/Keep + 120 s alarm
  → decision / timeout / dismissal
  → resolveDecision → history + cleanup
```

### Race conditions handled

- Download finishes during the 2-second analysis window.
- External cancellation (user cancels via Chrome download bar) while analysis runs.
- Repeated or concurrent decisions for the same download (idempotency guard via `activeResolutions` Set).
- Notification close events racing with button clicks.
- Service-worker restart with downloads in pending state (recovery from `chrome.storage.session`).
- Concurrent history writes (serialized via a promise queue).

### Fail-safe posture

| Condition | Outcome |
|---|---|
| Dangerous + notification cannot be created | Cancel / delete |
| Suspicious + notification cannot be created | Allow / keep |
| Timeout (120 s) on held download | Cancel |
| Timeout on completed risky file | Delete |
| Analysis throws unexpectedly | Treated as safe → resume |

---

## 7. Testing results

Run with `npm test` (`node --test`).

```
node --test  →  285 pass / 0 fail / 0 skipped
```

| Suite | Tests | Focus |
|---|---:|---|
| `lib/heuristics.test.js` | 56 | All 13 active detectors, extension parsing, hostname and URL extraction |
| `lib/i18n.test.js` | 36 | Four catalogues, fallbacks, named placeholder resolution, direction, reason codes, button order |
| `lib/threat/engine.test.js` | 32 | Provider normalization, every failure mode, provider-cannot-change-verdict invariant |
| `lib/scoring.test.js` | 23 | Score computation, all three sensitivity thresholds, trusted-domain bypass, hard-signal override |
| `lib/localization.test.js` | 23 | Real notification paths in all four languages; language-invariance of scores and verdicts |
| `lib/popup-core.test.js` | 20 | Single-send messaging, history rows, verdict badges, settings patch |
| `lib/page-alert.test.js` | 18 | Alert gating, payload localization, RTL, permission grant/denial, no URL in payload |
| `lib/completed_risk.test.js` | 16 | Completed-but-risky path, delete/keep, duplicate-notification guard |
| `lib/history.test.js` | 11 | Schema normalization, write-queue ordering, 100-entry cap |
| `lib/settings.test.js` | 6 | Defaults, retired-key stripping, language persistence |
| `lib/alert.test.js` | 7 | Notification text builders, truncation |
| `lib/analysis_race.test.js` | 4 | State changes during the analysis window |
| `lib/decision.test.js` | 4 | Decision idempotency |
| `lib/originating-tab.test.js` | (included above) | Tab resolution strategy |
| `lib/radar-ui.test.js` | (included above) | Radar markup and state |

Tests load the **real shipped `_locales` files** rather than fixtures, so a missing or
untranslated key fails the suite.

### Browser verification

Chrome for Testing 154.0.8037.92, unpacked extension, driven over the DevTools Protocol against
real downloads from local HTTP servers (throttled for the held path, fast for the completed path).

| Check | Result |
|---|---|
| Default popup Arabic / RTL | pass |
| English selection repaints popup, switches to LTR | pass |
| Language preference persists across popup close/reopen | pass |
| Held-risk notification: English title, message, reasons, buttons | pass |
| Held-risk notification: Arabic | pass |
| Completed-risk notification: English, Delete/Keep labels | pass |
| Completed-risk notification: Arabic | pass |
| Allow: resumes download | pass |
| Cancel: stops download | pass |
| Delete: removes file from disk | pass |
| Keep: leaves file untouched | pass |
| History renders in both languages | pass |
| Verdict badge on correct edge per text direction | pass |
| `sensitivity` / `enabled` survive a language switch | pass |

**Linting: not run, no result claimed.** `eslint.config.js` exists but `eslint` is not
declared in `package.json`, no lockfile, no lint script.

---

## 8. Evaluation matrix

The following test cases are reproducible: run `npm test` to re-derive every result. All scores
and verdicts are produced by `lib/scoring.js`. **No accuracy percentage is claimed** because no
labeled malware dataset has been used.

| Case | File name | URL | Signals fired | Score | Low | Medium | High |
|---|---|---|---|---:|---|---|---|
| T-1 Safe | `report.pdf` | `https://cdn.example.com/report.pdf` | none | 0 | safe | safe | safe |
| T-2 Low-risk executable | `setup.exe` | `https://cdn.example.com/setup.exe` | EXECUTABLE_EXTENSION | 25 | safe | safe | suspicious |
| T-3 Suspicious | `setup.exe` | `http://192.168.1.1/setup.exe` | EXECUTABLE_EXTENSION, INSECURE_HTTP, IP_HOST | 55 | suspicious | suspicious | suspicious |
| T-4 Dangerous (double ext) | `invoice.pdf.exe` | `https://cdn.example.com/invoice.pdf.exe` | DOUBLE_EXTENSION, EXECUTABLE_EXTENSION | 65 | suspicious | dangerous | dangerous |
| T-5 Dangerous (combined) | `invoice.pdf.exe` | `http://192.168.1.1/invoice.pdf.exe` | DOUBLE_EXTENSION, EXECUTABLE_EXTENSION, INSECURE_HTTP, IP_HOST | 95 | dangerous | dangerous | dangerous |
| T-6 Trusted bypass | `setup.exe` | `https://cdn.example.com/setup.exe` (trusted) | TRUSTED_DOMAIN | 0 | safe | safe | safe |
| T-7 Trust + hard signal | `invoice.pdf.exe` | `https://cdn.example.com/invoice.pdf.exe` (trusted) | DOUBLE_EXTENSION, EXECUTABLE_EXTENSION | 65 | suspicious | dangerous | dangerous |

**Observations:**
- T-2 demonstrates false-positive risk: a legitimate `.exe` is flagged at high sensitivity.
- T-4 shows that a double extension alone (without any network signal) already produces a `dangerous` verdict at medium sensitivity (score 65 ≥ 60).
- T-6 and T-7 confirm the trusted-domain bypass and hard-signal override work as specified.
- Score 95 in T-5 is not clamped to 100 because the raw sum (95) is within range; the cap would activate at ≥101 raw points.

---

## 9. Release

**No 0.2.0 package has been built.** The existing `cyber-guard-v0.1.1.zip` remains the current
released artifact and is **not** overwritten. Files named `*-SUPERSEDED-*.zip` are older builds
retained for reference only — do not install or distribute them.

**Why 0.2.0.** Four languages, a rebrand, a threat-state layer, a provider abstraction, and an
optional page-alert capability constitute a feature expansion, so the minor version moves.

**Build contents.** `manifest.json`, `background.js`, `popup.html`, `popup.css`, `popup.js`,
`_locales/{en,ar,es,fr}/messages.json`, `lib/{alert,heuristics,history,i18n,page-alert,popup-core,scoring}.js`,
`lib/threat/{provider,engine}.js`, three icon PNGs — 17 entries. Tests and documentation
excluded.

**Store naming.** The manifest name is sourced from `_locales` as *Cyber Guard: Download Security
Assistant*. Listings must keep describing real capability only. Do not claim VirusTotal, real-time
scanning, or malware detection until those capabilities genuinely exist.

---

## 10. Known limitations

- **Heuristics only; no content, hash, or reputation analysis.** A harmful file with an ordinary name from an ordinary URL passes.
- **Not all downloads are analyzed.** Downloads already finished, or no longer pausable, when first seen are skipped.
- **Fixed 2-second analysis window.** Not configurable.
- **Completed suspicious files are deleted** on timeout or notification dismissal, without an explicit user choice.
- **History records only risky downloads that reached a decision.** The decision cause is stored but not displayed.
- **`autoResumeSafe` is stored but unused.** `trustedDomains` has no UI.
- **Redirect-chain tracking is not implemented.** `buildContext()` in `background.js` hardcodes `redirectChain: []` because Chrome's downloads API does not expose redirect history. The `LONG_REDIRECT_CHAIN` heuristic therefore never fires in production.
- **Lookalike-domain detection is not implemented.** `checkLookalikeDomain()` is a stub that always returns null.
- **No external threat-intelligence provider.** The provider interface is in place, but nothing is queried; all verdicts come from local heuristics.
- **The completed-download duplicate-notification guard resets** on service-worker restart.
- **Analysis errors fail open** — an unexpected error is treated as `safe`.
- **No reproducible lint setup.** `eslint.config.js` exists; ESLint is not declared in `package.json`.
- **Not published** to the Chrome Web Store.
