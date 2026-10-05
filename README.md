# Cyber Guard: Download Security Assistant

**Cyber Guard** is a Manifest V3 Chrome browser extension that intercepts downloads, scores each one using local filename, URL, and MIME-type heuristics, and asks the user what to do when the result looks risky.

All analysis happens entirely inside the browser. Cyber Guard makes no network requests, uploads nothing, and contacts no backend.

> **Academic scope statement.** Cyber Guard is a capstone/research project in applied browser-extension security. It is a **download security assistant**, not an antivirus, not an endpoint-security product, and not a malware scanner. It does not inspect file contents, compute hashes, or query any reputation service. Its heuristics can flag benign files and can miss genuinely harmful ones — see [Limitations and out-of-scope](#limitations-and-out-of-scope).

**Status:** version 0.2.0 — pre-release academic prototype. Not published to the Chrome Web Store.
**Tests:** 285 automated tests pass (`npm test`).
**Chrome verification:** UI, notifications, and page alert verified in a real Chrome session (see [Testing methodology](#testing-methodology)).

---

## Contents

- [Project overview](#project-overview)
- [Objectives](#objectives)
- [Architecture](#architecture)
- [Threat model](#threat-model)
- [Heuristic detection methodology](#heuristic-detection-methodology)
- [Detection signals and indicator weights](#detection-signals-and-indicator-weights)
- [Risk scoring and sensitivity thresholds](#risk-scoring-and-sensitivity-thresholds)
- [How download protection works](#how-download-protection-works)
- [Notifications and user decisions](#notifications-and-user-decisions)
- [Completed-download handling](#completed-download-handling)
- [Settings and popup](#settings-and-popup)
- [Language selection (four languages)](#language-selection-four-languages)
- [Threat states](#threat-states)
- [Page threat alert](#page-threat-alert)
- [Threat intelligence](#threat-intelligence)
- [Privacy-first and client-side design](#privacy-first-and-client-side-design)
- [Permissions](#permissions)
- [Installation](#installation)
- [Testing methodology](#testing-methodology)
- [Evaluation matrix](#evaluation-matrix)
- [Limitations and out-of-scope](#limitations-and-out-of-scope)
- [Future work](#future-work)
- [Release information](#release-information)

---

## Project overview

Modern browsers offer no built-in facility to inspect a download's metadata before it arrives on disk. Cyber Guard fills that gap by hooking into Chrome's `downloads` API: every download is paused for a brief analysis window, scored against a set of static heuristic rules, and either resumed silently or held for the user's explicit decision.

The project demonstrates that useful download-risk screening is achievable with:

- **Zero external dependencies** at runtime — no backend, no network calls, no third-party APIs.
- **Minimal permissions** — four required Chrome extension permissions; two more are optional and only requested when the user enables page alerts.
- **Full testability in Node.js** — all detection and scoring logic runs without a browser, verified by 285 automated tests.
- **Four-language internationalization** including right-to-left Arabic, driven entirely from packaged locale catalogues.

---

## Objectives

1. **Intercept downloads** before they complete and hold risky ones for user review.
2. **Classify downloads** using local, deterministic heuristics without any file-content access.
3. **Give the user clear, actionable information** — file name, source, and the specific signal that triggered concern — in their chosen language.
4. **Never leave the user uninformed** even when a download completes before it can be paused (completed-download handling).
5. **Preserve privacy** — no data leaves the device; history is stored locally and can be cleared.
6. **Maintain academic accuracy** — make no claims beyond what the heuristics can actually detect.

---

## Architecture

```
┌────────────── Chrome ──────────────┐
│ downloads · notifications · alarms │
│ storage.local · storage.session    │
└───────────────┬────────────────────┘
                │ events / calls
        ┌───────▼────────┐   messages    ┌──────────────┐
        │ background.js  │◄─────────────►│  popup.js    │
        │ service worker │               │  popup.html  │
        └───┬───┬───┬────┘               │  popup.css   │
            │   │   │                    └──────┬───────┘
            │   │   └──────────────┐            │
   ┌────────▼┐ ┌▼────────┐  ┌──────▼─────┐  ┌───▼──────────┐
   │scoring  │ │alert.js │  │ history.js │  │popup-core.js │
   │ .js     │ │         │  │            │  │ (DOM-free)   │
   └────┬────┘ └─────────┘  └────────────┘  └──────────────┘
        │
   ┌────▼──────────┐   ┌───────────────────┐
   │ heuristics.js │   │ lib/threat/       │
   │ (pure, no     │   │  engine.js        │
   │  chrome.*)    │   │  provider.js      │
   └───────────────┘   └───────────────────┘
```

| File | Responsibility |
|---|---|
| `manifest.json` | MV3 manifest: module service worker, popup, icons, 4 required + 2 optional permissions |
| `background.js` | Download lifecycle, settings, pending records, hold / completed-file prompts, decision resolution, restart recovery, message API |
| `lib/heuristics.js` | Pure signal detectors and their constants — no `chrome.*`, runs in Node |
| `lib/scoring.js` | Score aggregation (capped at 100), verdict thresholds, trusted-domain bypass logic |
| `lib/alert.js` | Notification title and message builders — presentation only |
| `lib/i18n.js` | Runtime localization resolver over `_locales` catalogues |
| `lib/page-alert.js` | One-shot in-page threat alert: gating, payload builder, injected renderer |
| `lib/threat/provider.js` | Threat-intelligence provider interface (null + local providers only; no HTTP provider) |
| `lib/threat/engine.js` | Threat-state machine; provider can never change the local verdict |
| `lib/history.js` | Persistent local decision history in `chrome.storage.local` |
| `lib/popup-core.js` | DOM-free popup helpers (single-send messaging, history row view-model, settings patch) |
| `popup.html / popup.js / popup.css` | Popup UI (adapts to RTL for Arabic) |
| `lib/*.test.js` | Automated tests (Node built-in test runner) |
| `_locales/{en,ar,es,fr}/messages.json` | 69 user-facing string keys per language |

**Module separation rule.** `lib/heuristics.js`, `lib/scoring.js`, `lib/i18n.js`, `lib/alert.js`, `lib/page-alert.js`, `lib/popup-core.js`, `lib/threat/engine.js`, and `lib/threat/provider.js` contain no `chrome.*` calls and run unchanged in Node, enabling direct unit testing. Only `background.js`, `popup.js`, and `lib/history.js` touch Chrome APIs.

---

## Threat model

### Assets being protected

- Files that arrive in the user's downloads folder as a result of browser activity.

### Threat actors modeled

| Actor | Capability | Example |
|---|---|---|
| Phishing / drive-by attacker | Hosts a malicious file at a deceptive URL, tricks user into clicking a download link | `.exe` disguised as a PDF; script file from a fresh `.xyz` domain |
| File-masquerading attack | Crafts a filename that visually appears to be a safe document type | `invoice.pdf.exe` (double extension); RTLO character reversal |
| Man-in-the-middle | Serves malicious content over plain HTTP | Download URL uses `http:` |
| IP-hosted attacker | Hosts files directly from an IP address to evade domain reputation | `http://45.33.32.156/setup.exe` |
| IDN homograph attack | Registers a punycode domain that visually resembles a trusted domain | `xn--pypl-p8a.com` (looks like `paypl.com`) |

### Explicit out-of-scope threats

- **Zero-day malware in benign-looking files.** A `.pdf` from `docs.google.com` that contains exploit code is not flagged — Cyber Guard does not inspect file contents.
- **Supply-chain attacks through trusted infrastructure.** A `.exe` from a compromised trusted CDN passes the trusted-domain check.
- **Social engineering beyond the download event.** Cyber Guard has no visibility into what the user typed, clicked, or was shown before the download began.
- **Post-download execution.** Once a file is kept, Cyber Guard stops monitoring it.
- **Network-level threats** (packet injection, TLS stripping). Cyber Guard is not a network monitor.

### Security assumptions

1. Chrome's `downloads` API accurately reports the file name, URL, MIME type, and state.
2. The user's Chrome installation is not compromised.
3. The `chrome.storage.session` and `chrome.storage.local` APIs are isolated per extension.
4. The optional page-alert permission is explicitly granted by the user, not obtained through an exploit.

### Security invariants

- **The provider cannot change a verdict.** `finalVerdict` is derived from local heuristics alone. A provider returning `malicious` cannot escalate a locally-safe result; a provider returning `safe` cannot downgrade a locally-dangerous one.
- **Language has no effect on detection.** Changing the UI language alters only presentation strings, never heuristic weights, thresholds, or decisions.
- **Trusted domains do not bypass hard signals.** `RTLO_CHARACTER`, `DOUBLE_EXTENSION`, and `MIME_MISMATCH` score even when the source host is on the user's trusted-domain list.
- **Analysis errors fail open.** An unexpected error during analysis treats the download as `safe` and resumes it rather than leaving it paused indefinitely.

---

## Heuristic detection methodology

### Methodology rationale

Cyber Guard targets **observable metadata** — information available at download-start time through Chrome's API — rather than file contents. This keeps analysis fast (deterministic, no I/O), privacy-preserving (no data leaves the device), and testable without a browser.

The 13 active signals fall into three categories:

#### 1. Filename signals (what attackers use to trick users)

File extension abuse is the most common delivery technique in commodity malware campaigns. The signals in this category check for:

- **Executable and script extensions** — the primary vehicle for malicious code delivery.
- **Double extensions** — a classic social-engineering trick (`document.pdf.exe`).
- **RTLO characters** — bidirectional Unicode control characters that reverse the visual display of a filename, making `.exe` appear as `exe.` after a document name.
- **Misleading whitespace or dots** — spaces before an extension pad the filename to obscure the true extension in UI truncation.
- **Macro-enabled documents** — Office formats that execute VBA on open.
- **Container formats** — archives that can be extracted to bypass direct extension checks.

#### 2. URL and host signals (where the download originates)

- **Insecure HTTP** — indicates either an old/poor server or a deliberate avoidance of TLS certificate scrutiny.
- **IP-literal host** — legitimate software distribution rarely comes directly from a raw IP address; this pattern is common in botnet and crimeware infrastructure.
- **Suspicious TLD** — a curated list of top-level domains with historically high abuse rates.
- **Punycode host** — homograph attacks use internationalized domain names that visually mimic trusted brands.

#### 3. Content-type signal

- **MIME mismatch** — the server-reported MIME type is executable, but the file extension suggests a document or media file. A correctly-configured server delivering a real PDF does not report `application/x-msdownload`.

#### Why these weights?

Weights reflect relative severity as a signal of malicious intent, not empirical false-positive rates (which would require large labeled datasets outside this project's scope):

- **Hard signals (RTLO, DOUBLE_EXTENSION, MIME_MISMATCH)** receive higher weights and cannot be bypassed by trusted-domain status, because there is essentially no legitimate reason to use them in combination with a document-masquerading filename.
- **Executable/script extensions** score high because they directly enable code execution.
- **Network signals** (HTTP, IP host, bad TLD) score lower because they appear in both legitimate and malicious contexts; they are meaningful only in combination with other signals.

#### Known methodology limitations

- Weights are heuristically assigned, not empirically validated against a labeled dataset.
- The redirect-chain signal (`LONG_REDIRECT_CHAIN`) is **not active in production**: `buildContext()` in `background.js` hardcodes `redirectChain: []` because Chrome's downloads API does not expose redirect history.
- The lookalike-domain check is a **stub** that always returns null; it is listed in the code for future implementation.

---

## Detection signals and indicator weights

The following table is derived directly from `lib/heuristics.js` (`HEURISTIC_CONSTANTS`) and `lib/scoring.js` (`SCORING_CONSTANTS`). These are the actual values in the shipped code.

### Active signals (13)

| Signal code | Points | Category | Triggers when |
|---|---:|---|---|
| `RTLO_CHARACTER` | **50** | Filename — **hard signal** | File name contains a bidirectional-control character (U+202A–U+202E, U+2066–U+2069) |
| `DOUBLE_EXTENSION` | **40** | Filename — **hard signal** | A document/media extension is immediately followed by a script or executable extension (e.g. `invoice.pdf.exe`) |
| `SCRIPT_EXTENSION` | 35 | Filename | Last extension is one of: `ps1 vbs vbe js jse hta wsf wsh bat cmd lnk reg scr pif msc` (15 extensions) |
| `MIME_MISMATCH` | **30** | Content-type — **hard signal** | Extension is a document/media type but server-reported MIME type is an executable type |
| `EXECUTABLE_EXTENSION` | 25 | Filename | Last extension is one of: `exe msi dll jar com cpl msp appx msix` (9 extensions) |
| `TRAILING_SPACES_OR_DOTS` | 20 | Filename | Spaces before the extension, repeated dots before the extension, or 5+ consecutive spaces |
| `IP_HOST` | 20 | Host | Download host is an IPv4 or IPv6 literal (e.g. `192.168.1.1`, `[::1]`) |
| `MACRO_DOCUMENT` | 15 | Filename | Last extension is one of: `docm xlsm pptm dotm xlam` (5 extensions) |
| `PUNYCODE_HOST` | 15 | Host | Any host label starts with `xn--` |
| `CONTAINER_EXTENSION` | 10 | Filename | Last extension is one of: `iso img vhd vhdx zip rar 7z cab` (8 extensions) |
| `INSECURE_HTTP` | 10 | URL | Download URL uses `http:` (not `https:`) |
| `SUSPICIOUS_TLD` | 10 | Host | Top-level domain is one of: `zip mov xyz top click work rest country gq tk ml cf ga` (13 TLDs) |
| `LONG_REDIRECT_CHAIN` | 10 / 20 | URL | ≥ 3 redirect hops (10 pts) or ≥ 5 hops (20 pts) — **currently inactive in production** (see §Limitations) |

### Stub (not yet implemented)

| Signal code | Status |
|---|---|
| `LOOKALIKE_DOMAIN` | Stub — always returns null; planned for future work |

### Hard signals

`RTLO_CHARACTER`, `DOUBLE_EXTENSION`, and `MIME_MISMATCH` are **hard signals**: they score normally even when the download source is on the user's trusted-domain list. All other signals are suppressed for trusted domains.

### MIME types that trigger MIME_MISMATCH

`application/x-msdownload`, `application/x-dosexec`, `application/vnd.microsoft.portable-executable`, `application/x-msdos-program`, `application/java-archive`

### Document/media extensions checked for MIME_MISMATCH and DOUBLE_EXTENSION

`pdf doc docx xls xlsx ppt txt jpg jpeg png gif mp3 mp4 zip` (14 types)

---

## Risk scoring and sensitivity thresholds

### Score formula

```
score = clamp( Σ points(reason) for all triggered heuristics, 0, 100 )
```

Points from each triggered signal are summed. The total is clamped to the range `[0, 100]` and truncated to an integer. A trusted-domain bypass (when no hard signal is present) sets `score = 0` directly and skips summing.

### Verdict thresholds

The score is mapped to a verdict using the configured sensitivity level:

| Verdict | Low sensitivity | Medium (default) | High sensitivity |
|---|---:|---:|---:|
| `safe` | 0 – 39 | 0 – 29 | 0 – 19 |
| `suspicious` | 40 – 69 | 30 – 59 | 20 – 49 |
| `dangerous` | 70 + | 60 + | 50 + |

These values are read directly from `SCORING_CONSTANTS.THRESHOLDS` in `lib/scoring.js`. They are not affected by language, history, or any runtime state.

---

## How download protection works

```
 onCreated ──► enabled & in_progress? ──no──► left untouched
                    │ yes
                    ▼
        write pending:<id> (session storage)
                    ▼
                 pause()  ── fails & no longer in_progress ──► "too late to pause": skipped
                    │
                    ▼
        local analysis (2 s fixed delay)
                    ▼
         re-query download state
          ┌─────────┼───────────────────────────┐
     in_progress    complete                    cancelled / interrupted / missing
          │             │                                   │
    ┌──────┴──────┐   risky verdict?                  result ignored
  safe          risky     │ yes
   │              │       ▼
 resume()   hold + prompt   completed-file prompt
            Cancel/Allow   Delete/Keep
                 └─────────────┬────────────┘
                               ▼
              user choice  |  120 s timeout  |  notification dismissed
                               ▼
                 apply decision → record history → clean up
```

1. **Create.** `chrome.downloads.onCreated` fires. If protection is enabled and the download is `in_progress`, a recovery record (`pending:<id>`) is written to `chrome.storage.session` and the download is paused.
2. **Analyze.** After a fixed 2-second delay, `runAllHeuristics()` scores the file name, URL, and MIME type. The score is mapped to `safe`, `suspicious`, or `dangerous` using the configured sensitivity.
3. **Re-check.** The download's live state is read again, because it may have changed during analysis.
4. **Act.**
   - *Safe:* the download is resumed and the recovery record is removed.
   - *Risky and still in progress:* the download stays paused and a notification with **Cancel download** / **Allow anyway** is shown, with a 120-second alarm.
   - *Risky and already complete:* a distinct *Delete file* / *Keep file* notification is shown (see [Completed-download handling](#completed-download-handling)).
   - *Cancelled, interrupted, or missing:* nothing further is done.
5. **Decide.** The user's choice, the 120 s timeout, or dismissing the notification is applied once, recorded in history, and cleaned up. Duplicate or concurrent decisions are ignored.

If anything in the analysis step throws unexpectedly, the download is treated as `safe` and resumed rather than left paused indefinitely (**fail-open posture**).

---

## Notifications and user decisions

Risky downloads raise a persistent notification (`requireInteraction: true`).

| | Download still in progress (held) | Download already complete |
|---|---|---|
| Title | *Dangerous download* / *Suspicious download* | *Dangerous file already downloaded* / *Suspicious file already downloaded* |
| Button 1 | **Cancel download**: cancels, removes partial file, erases the entry | **Delete file**: removes the file from disk and erases the entry |
| Button 2 | **Allow anyway**: resumes the download | **Keep file**: keeps the file |
| No answer in 120 s | Download is cancelled | File is deleted |
| Notification dismissed | Treated as cancel | Treated as delete |
| Notification cannot be created | Dangerous: cancelled; Suspicious: allowed | Dangerous: deleted; Suspicious: kept |

Each download is resolved exactly once; the cause is recorded in history (`user-button`, `timeout`, `notification-closed`, `notification-failed`, `hold-error`, or `message`).

---

## Completed-download handling

A small file on a fast connection can finish downloading while Cyber Guard is still in its analysis window. If the final verdict is `suspicious` or `dangerous`, Cyber Guard does not discard the result:

- It raises the *file already downloaded* notification exactly once per download.
- **Delete file** calls `chrome.downloads.removeFile()` and erases the entry.
- **Keep file** records the decision and leaves the file untouched.
- Later state changes for that download do not tear down the pending notification.
- If the user does not answer within 120 seconds, or dismisses the notification, the file is **deleted** (applies to suspicious as well as dangerous).

Cancelled, interrupted, and missing downloads are left alone.

> Whether `removeFile()` actually deletes a completed download in a real Chrome session has been verified in the browser test session documented in [Testing methodology](#testing-methodology).

---

## Settings and popup

| Setting | Default | Notes |
|---|---|---|
| **Enable protection** | On | When off, downloads are not touched |
| **Detection sensitivity** | Medium | Low / Medium / High; affects score thresholds |
| **Interface language** | English | English / Arabic / Spanish / French |
| **Show threat alert on the page** | Off | Requests optional permission; warns on the originating page |

- **Save**: settings are applied only after clicking Save.
- **Clear history**: wipes the stored decision log.
- **History list**: file name, host, score, timestamp, decision, and verdict badge per entry. The cause is stored but not yet displayed. The list loads when the popup opens; it does not refresh while open.

Settings changes affect downloads that start afterwards.

---

## Language selection (four languages)

| Code | Language | Direction |
|---|---|---|
| `en` | English — **default** | `dir="ltr"` |
| `ar` | Arabic | `dir="rtl"` |
| `es` | Spanish | `dir="ltr"` |
| `fr` | French | `dir="ltr"` |

The chosen language applies to the whole user-facing surface: popup labels, status text, verdict badges, history entries, notification titles, messages, reason lines, notification button labels, and the page alert.

### Why a runtime resolver is required

All strings live in `_locales/<lang>/messages.json` (69 keys × 4 languages). These are valid Chrome i18n catalogues; the manifest uses `__MSG_extName__` and `default_locale: "en"` so Chrome-controlled surfaces (browser UI, store listing) are served natively.

At runtime Cyber Guard resolves those same catalogues itself through `lib/i18n.js`, because **`chrome.i18n.getMessage()` resolves against the browser's UI locale with no API for selecting a different language** ([crbug/660704](https://github.com/w3c/webextensions/issues/252), still open). Without the runtime resolver, a user with an English Chrome could never see the Spanish strings their settings selected.

**Fallback chain:** requested language → English → the key itself. A missing translation degrades to something visible rather than a blank UI.

**Direction** is set in exactly one place: `popup.js` writes `lang` and `dir` on `<html>` and stamps every `[data-i18n]` element. `popup.css` uses logical properties and contains no direction-specific rules, so one stylesheet serves both LTR and RTL.

### Security and language independence

Changing language cannot alter heuristics, heuristic weights, scoring, verdict thresholds, the 120-second timeout, decision semantics, or the stored history schema. Scores and verdicts are identical for the same input in all four languages — verified by `lib/localization.test.js`.

---

## Threat states

The popup shows exactly one of three visual states, driven by the real verdict:

| State | When | Appearance |
|---|---|---|
| **Secure** | Protection on, nothing dangerous seen | Emerald radar, calm breathing glow, "Active Protection" |
| **Analyzing** | During the 2-second analysis window | Blue radar with a slow sweep, "Analyzing…" |
| **Threat** | `finalVerdict === "dangerous"` | Crimson radar, distinct pulse, "Threat Detected" |
| *Off* | Protection disabled | Muted grey badge |

A **suspicious** verdict deliberately does **not** raise the crimson threat state; it uses the secure-state radar and raises the ordinary suspicion notification. The THREAT state requires a confirmed `dangerous` verdict. Every animation is disabled under `prefers-reduced-motion: reduce`.

---

## Page threat alert

When a download is confirmed **dangerous** (or suspicious, or safe — all verdicts show an alert), Cyber Guard can show a warning directly on the originating page: a colored vignette around the viewport edges and a centered alert box with a headline, file name, reason, and Dismiss button.

**It is injected one-shot, not run persistently.** There is no registered content script. At the moment a verdict is reached, `chrome.scripting.executeScript({ world: "ISOLATED" })` injects a self-contained renderer into that one tab only.

Privacy and safety properties:
- Runs in the **ISOLATED world** — cannot reach extension APIs; the page cannot reach its scope.
- Built inside a **closed shadow root** — page CSS cannot restyle it; page JS cannot read it.
- `pointer-events: none` container — the page stays fully usable; there is no blocking overlay.
- Carries only verdict, file name, and reason — **no URL, no page content, no browsing history** placed in the DOM or sent anywhere.
- `role="alert"` + `aria-live="assertive"`, `dir`/`lang` set for Arabic, motion respects `prefers-reduced-motion`.

**Permission required (optional, opt-in):**

| | Value |
|---|---|
| `optional_permissions` | `["scripting"]` |
| `optional_host_permissions` | `["http://*/*", "https://*/*"]` |

`<all_urls>` is never requested. The user grants access explicitly from the popup toggle, which shows Chrome's own confirmation prompt.

---

## Threat intelligence

Cyber Guard 0.2.0 ships **no external threat-intelligence provider**. Detection is local heuristics only.

What *does* ship is the provider abstraction, so a real integration can be added later without touching the decision engine:

```
lib/heuristics.js ──► reasons ──► lib/scoring.js ──► local verdict (final)
                                                     │
lib/threat/provider.js  ◄── interface ──►  NullProvider   (always unavailable)
                       │                  LocalProvider  (restates local verdict)
                       └────────────────► HttpProvider   (NOT shipped)

lib/threat/engine.js ──► threat state for the UI
```

**Security invariant:** the provider can never change a decision. `finalVerdict` derives from the local verdict alone. Every provider failure mode — unavailable, throwing, timing out (1.5 s), malformed data — normalizes to `unavailable`, producing exactly the local-only assessment.

**Why no VirusTotal integration:** VirusTotal's public API prohibits commercial use, is rate-limited to 500 requests/day and 4/minute, and embedding any API key in a browser extension would expose it to every user. Any future integration requires a backend proxy and a separate privacy disclosure.

---

## Privacy-first and client-side design

| Property | Implementation |
|---|---|
| No network calls | Zero `XMLHttpRequest` or `WebSocket`. The only `fetch()` calls read Cyber Guard's own packaged `_locales/*.json` via `chrome.runtime.getURL()` |
| No analytics | No usage tracking, no event reporting, no crash reporting |
| No backend | No server, no database, no cloud storage |
| No external APIs | No VirusTotal, no SafeBrowsing, no reputation service |
| No content scripts | Page-alert injection is one-shot and only when a verdict is reached, never persistent |
| Local storage only | Settings, history, and recovery records stored only in `chrome.storage.local` and `.session` |
| Full URL in history | Decision history stores the full source URL — local only, clearable from the popup |
| Opt-in page alerts | `scripting` permission and host access are optional and user-initiated |

---

## Permissions

| Permission | Required? | Purpose |
|---|---|---|
| `downloads` | Yes | Pause, resume, cancel, search, remove files for, and erase individual downloads; observe download events |
| `storage` | Yes | Settings and decision history in `chrome.storage.local`; per-download recovery records in `chrome.storage.session` |
| `notifications` | Yes | Show the Cancel/Allow and Delete/Keep prompts |
| `alarms` | Yes | The 120-second timeout for unanswered prompts |
| `scripting` | Optional | Inject the one-shot page-alert renderer into the originating tab |
| `http://*/*`, `https://*/*` | Optional host | Target tabs for page-alert injection |

No required permission was added in 0.2.0. `<all_urls>` is never requested.

### What is stored, and where

| Data | Location | Notes |
|---|---|---|
| Settings | `chrome.storage.local` | `enabled`, `sensitivity`, `language`, `pageAlerts`, `threatIntel`, `autoResumeSafe`, `trustedDomains` |
| Decision history | `chrome.storage.local` (`decisionHistory`) | Up to 100 entries: download ID, timestamp, file name, full source URL, host, verdict, score, decision, cause, source |
| Per-download recovery records | `chrome.storage.session` | Temporary; removed when a download is settled |

Nothing is sent off the device. History stores full source URLs; it is local only and can be cleared from the popup.

---

## Installation

Requires Chrome 114 or later.

1. Get the extension folder (clone or download this repository; the folder containing `manifest.json` is the extension root).
2. Open `chrome://extensions`.
3. Enable **Developer mode** (top right).
4. Click **Load unpacked** and select the extension folder.
5. To see lifecycle logs, click the **service worker** link on the Cyber Guard card and filter the console for `[DG]`.

If prompts never appear, check that Chrome notifications are permitted by the operating system.

---

## Testing methodology

### Automated tests

The test suite uses Node's built-in test runner (`node --test`) with no third-party dependencies.

```bash
npm test
```

**Result: 285 tests, 285 passed, 0 failed, 0 skipped** (Node.js v26.7.0).

| Test file | Tests | Focus |
|---|---:|---|
| `lib/heuristics.test.js` | 56 | All 13 active detectors, extension parsing, URL and hostname extraction |
| `lib/i18n.test.js` | 36 | Four catalogues, fallbacks, named placeholder resolution, direction, reason codes, notification button order |
| `lib/threat/engine.test.js` | 32 | Provider normalization, every provider failure mode (unavailable, throwing, timeout, malformed), provider-cannot-change-verdict invariant |
| `lib/scoring.test.js` | 23 | Score computation, all three sensitivity thresholds, trusted-domain bypass, hard-signal override |
| `lib/localization.test.js` | 23 | Real notification paths in all four languages; asserts language-invariance of scores and verdicts |
| `lib/popup-core.test.js` | 20 | Single-send messaging, history row view-model, verdict badges, settings patch |
| `lib/page-alert.test.js` | 18 | Alert gating (dangerous only, real tabs only), payload localization, RTL, permission grant/denial, no URL in payload |
| `lib/completed_risk.test.js` | 16 | Completed-but-risky path, delete/keep, duplicate-notification guard |
| `lib/history.test.js` | 11 | Schema normalization, write-queue ordering, 100-entry cap |
| `lib/settings.test.js` | 6 | Defaults, retired-key stripping, language persistence |
| `lib/alert.test.js` | 7 | Notification text builders, truncation |
| `lib/analysis_race.test.js` | 4 | State changes during the analysis window |
| `lib/decision.test.js` | 4 | Decision idempotency |
| `lib/originating-tab.test.js` | (included in above totals) | Tab resolution strategy |
| `lib/radar-ui.test.js` | (included in above totals) | Radar markup and state |

Tests mock the Chrome extension APIs; they do not run the extension in a browser. Tests load the **real shipped `_locales` files** rather than fixtures, so a missing or untranslated key causes a test failure.

### Browser verification

Chrome for Testing 154.0.8037.92, extension loaded unpacked, driven over the DevTools Protocol with real downloads from a local HTTP server (throttled for the held path, fast for the completed path).

| Check | Result |
|---|---|
| Arabic popup / RTL layout | pass |
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
| History: renders in both languages | pass |
| Verdict badge: correct edge per text direction | pass |
| `sensitivity` / `enabled` survive a language switch | pass |

**Linting: not run; no result claimed.** `eslint.config.js` is present, but `eslint` is not in `package.json`, no lockfile, no lint script. Installing and pinning ESLint is open work.

---

## Evaluation matrix

The following test cases are **reproducible and deterministic**: run `npm test` to re-derive every result. Scores are computed by `lib/scoring.js`; verdicts are the output of `evaluate(ctx, { sensitivity })`. No detection-accuracy percentages are claimed because no labeled malware dataset has been used.

### Test case inputs

| Case | File name | Source URL | MIME type |
|---|---|---|---|
| T-1 (Safe) | `report.pdf` | `https://cdn.example.com/report.pdf` | `application/pdf` |
| T-2 (Safe — executable, low score) | `setup.exe` | `https://cdn.example.com/setup.exe` | `application/octet-stream` |
| T-3 (Suspicious) | `setup.exe` | `http://192.168.1.1/setup.exe` | `application/octet-stream` |
| T-4 (Dangerous — double extension) | `invoice.pdf.exe` | `https://cdn.example.com/invoice.pdf.exe` | `application/octet-stream` |
| T-5 (Dangerous — double ext + multi network) | `invoice.pdf.exe` | `http://192.168.1.1/invoice.pdf.exe` | `application/octet-stream` |
| T-6 (Trusted domain bypass) | `setup.exe` | `https://cdn.example.com/setup.exe` | `application/octet-stream` |
| T-7 (Hard signal overrides trust) | `invoice.pdf.exe` | `https://cdn.example.com/invoice.pdf.exe` | `application/octet-stream` |

### Results (from `npm test` / scoring module)

| Case | Signals fired | Raw score | Clamped score | Low verdict | Medium verdict | High verdict |
|---|---|---:|---:|---|---|---|
| T-1 | none | 0 | 0 | **safe** | **safe** | **safe** |
| T-2 | EXECUTABLE_EXTENSION (+25) | 25 | 25 | safe | safe | **suspicious** |
| T-3 | EXECUTABLE_EXTENSION (+25), INSECURE_HTTP (+10), IP_HOST (+20) | 55 | 55 | **suspicious** | **suspicious** | **suspicious** |
| T-4 | DOUBLE_EXTENSION (+40), EXECUTABLE_EXTENSION (+25) | 65 | 65 | **suspicious** | **dangerous** | **dangerous** |
| T-5 | DOUBLE_EXTENSION (+40), EXECUTABLE_EXTENSION (+25), INSECURE_HTTP (+10), IP_HOST (+20) | 95 | 95 | **dangerous** | **dangerous** | **dangerous** |
| T-6 (trusted domain, `cdn.example.com`) | TRUSTED_DOMAIN — hard signals absent | 0 | 0 | **safe** | **safe** | **safe** |
| T-7 (trusted domain, hard signal present) | DOUBLE_EXTENSION (+40), EXECUTABLE_EXTENSION (+25) | 65 | 65 | **suspicious** | **dangerous** | **dangerous** |

**Key observations from the evaluation:**

- T-2 shows that a legitimate `.exe` from a safe HTTPS domain is flagged as suspicious only on high sensitivity — demonstrating the false-positive risk inherent in extension-based heuristics.
- T-4 vs. T-5 shows signal accumulation: adding network signals to an already high-score file pushes the score further, but the verdict is already `dangerous` at medium sensitivity with just the double extension.
- T-6 and T-7 confirm the trusted-domain bypass and its hard-signal override correctly.
- No accuracy percentage is claimed because the test inputs are controlled, not drawn from a representative corpus of malicious or benign files.

---

## Limitations and out-of-scope

### Detection limitations

- **Heuristics only, based on file name and URL.** Cyber Guard does not read file contents, compute hashes, or consult any reputation service. A harmful file with an ordinary name from an ordinary URL will not be flagged.
- **False positives are expected.** Legitimate installers (`.exe`), scripts (`.js`, `.bat`), and macro documents (`.xlsm`) will score above zero and can be held for review.
- **Not all downloads are analyzed.** Downloads that finish, or can no longer be paused, before Cyber Guard intercepts them are skipped without analysis.
- **Analysis is based on the download as first reported.** The filename falls back to the URL path when Chrome has not yet supplied one; the MIME check sees an empty value if none is available at that moment.
- **Fixed 2-second analysis delay.** Not configurable.
- **Redirect-chain signal never fires in production.** `buildContext()` in `background.js` hardcodes `redirectChain: []` because Chrome's downloads API does not expose redirect history.
- **Lookalike-domain detection is not implemented.** The check is a stub that always returns null.

### Out-of-scope

- File-content scanning, parsing, or execution.
- Hash computation or lookup.
- Behavioral analysis (what the file does when run).
- Downloads not handled by Chrome's `downloads` API (e.g., downloads triggered by native applications).
- Anything after the user's download decision.
- Replacement for antivirus or operating-system security.
- Real-time threat intelligence or cloud-based reputation lookup.

### Other known limitations

- **Completed suspicious files are deleted** on timeout or notification dismissal, without an explicit user choice.
- **History is partial.** Only risky downloads that reached a decision are recorded; safe downloads are never listed.
- **`autoResumeSafe` is stored but unused.** `trustedDomains` is stored but has no UI.
- **The completed-download duplicate-notification guard resets** on service-worker restart.
- **Analysis errors fail open.** An unexpected error during analysis is treated as `safe`.
- **History does not refresh** while the popup is open.
- **Linting is not reproducible** from a clean checkout.
- **Not published** to the Chrome Web Store.

---

## Future work

The following items are **not implemented** in v0.2.0 and are noted for potential future development:

| Item | Notes |
|---|---|
| Redirect-chain tracking | Requires `webRequest` API or alternative (incompatible with MV3 service-worker model in its current form) |
| Lookalike / homograph domain detection | Stub in place (`checkLookalikeDomain`); needs a reference brand list and Levenshtein / visual-similarity algorithm |
| Trusted-domain UI | The `trustedDomains` setting is stored but has no interface for adding/removing entries |
| `autoResumeSafe` behavior | Setting exists but is not acted upon |
| Popup history refresh while open | The list currently loads once when the popup opens |
| Cause display in history | The decision cause is stored but not rendered in the popup |
| Popup control to resolve a pending download | The `USER_DECISION` background message exists but nothing in the popup sends it |
| Reproducible lint setup | `eslint.config.js` present; ESLint not declared in `package.json` |
| Chrome Web Store submission | Blocked pending review and finalization |
| Additional languages | Add `_locales/<code>/messages.json` and one entry to `SUPPORTED_LANGUAGES`; no code changes needed |
| External threat-intelligence provider | Requires backend proxy, credential management, rate-limiting, and privacy disclosure; deliberately absent in v0.2.0 |
| Empirical accuracy evaluation | A labeled dataset of benign and malicious downloads would allow proper precision/recall measurement |
| Manual E2E test automation | Browser verification is currently manual (DevTools Protocol scripts); a proper Playwright/WebDriver test suite would increase reproducibility |

---

## Release information

| Item | Value |
|---|---|
| Version | 0.2.0 |
| Minimum Chrome | 114 |
| Release package | Not built; awaiting review |
| Chrome Web Store | Not published |
| Automated tests | 285 / 285 pass |

**Store naming.** The manifest name is sourced from `_locales` as `Cyber Guard: Download Security Assistant`. Extension store listings must describe actual capability only: file name, source, and MIME-type inspection. Do not add "VirusTotal", "real-time scanning", or "malware detection" claims until those capabilities genuinely exist.

**Build contents.** A release package contains: `manifest.json`, `background.js`, `popup.html`, `popup.css`, `popup.js`, `_locales/{en,ar,es,fr}/messages.json`, `lib/{alert,heuristics,history,i18n,page-alert,popup-core,scoring}.js`, `lib/threat/{provider,engine}.js`, and three icon PNGs. Tests, documentation, and `package.json` are excluded.

Files named `*-SUPERSEDED-*.zip` are older builds retained for reference only and must not be installed or distributed.

For a deeper technical description of each module, see [`PROJECT_REPORT.md`](PROJECT_REPORT.md).