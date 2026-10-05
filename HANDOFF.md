# Cyber Guard — Partner Handoff Report

**Prepared:** 2026-10-05
**Revision:** 5 — four languages, Closed Radar rebrand, threat states, provider abstraction, page alert
**Status:** PR #1 open, not merged. Nothing published to the Chrome Web Store. **No release ZIP built for this revision — awaiting review.**

---

## 0. Revision 5 — 0.2.0 feature expansion

### What shipped

| Area | Change |
|---|---|
| Localization | `_locales/{en,ar,es,fr}/messages.json` (69 keys each) + runtime resolver in `lib/i18n.js`. **English is the new default**; existing stored preferences are preserved. |
| Manifest | `default_locale`, `__MSG_*__` name/description, version `0.2.0`, two **optional** permissions |
| Brand | Closed Radar: new `icons/radar.svg` + regenerated 16/48/128 PNGs, new palette, system font stack |
| Popup | Radar logo with secure / analyzing / threat states, red threat badges, `prefers-reduced-motion` guards |
| Threat layer | `lib/threat/provider.js` + `lib/threat/engine.js`: provider interface, `NullProvider`, `LocalProvider`, threat-state machine. **No HTTP provider.** |
| Page alert | `lib/page-alert.js`: one-shot `chrome.scripting.executeScript()` injection into the originating tab, closed shadow root, opt-in permission |

### Language architecture and the one honest compromise

`chrome.i18n.getMessage()` resolves against the **browser UI locale** and has no API for
requesting a specific language ([crbug/660704](https://github.com/w3c/webextensions/issues/252),
still open). It therefore cannot drive a runtime language selector.

The hybrid adopted here:

- **Native `_locales` + `__MSG_*__` + `default_locale: "en"`** serve every Chrome-controlled
  surface — the manifest name/description, the browser UI, and the store listing.
- **`lib/i18n.js` resolves the same catalogues at runtime**, reading
  `_locales/<lang>/messages.json` through `chrome.runtime.getURL()` and passing the stored
  preference explicitly. This is what makes the runtime selector work.

The two `fetch()` calls in the codebase read only Cyber Guard's own packaged files. There is no
network access.

Consequence to be aware of: adding a language means adding a `_locales` folder and one entry in
`SUPPORTED_LANGUAGES`. Chrome's own UI chrome follows the *browser* locale, not the in-app
selection — that is a browser limitation, not a bug in this implementation.

### The default-language change is a real data change

0.2.0 defaults to English (the 0.1.x default was Arabic). This is deliberate and matches the
store-facing decision to make English primary, but reviewers should understand:

- Users on **0.1.x stored an explicit `language`**, so **their choice is preserved**. An Arabic
  user stays on Arabic.
- Only installs with **no stored value** — i.e. pre-localization builds, and fresh installs —
  pick up English.

There is no migration and nothing is rewritten.

### Threat-intelligence layer: interface only, no provider

```
lib/heuristics.js ──► reasons ──► lib/scoring.js ──► local verdict
                                                     │
lib/threat/provider.js  ◄── interface ──►  NullProvider    (always unavailable)
                       │                  LocalProvider   (restates the local verdict)
                       └────────────────►  HttpProvider    (NOT implemented)

lib/threat/engine.js ──► threat state for the UI
```

**Security invariant: a provider can never change a decision.** `finalVerdict` comes from the
local verdict alone. A `malicious` provider cannot escalate a locally-safe download; a `safe`
provider cannot downgrade a locally-dangerous one. Failure modes — unavailable, throwing,
timing out (1.5 s guard), malformed payload — all normalize to `unavailable` and yield exactly
the local-only assessment. Each is covered by a test.

**No VirusTotal integration, deliberately.** Their public API must not be used in commercial
products (500 req/day, 4/min, permanent ban for non-compliance); only the paid Private API
permits commercial use; and any key embedded in an extension is exposed to every user. Any future
integration must go through a backend proxy holding the credential, with its own privacy
disclosure. Cyber Guard sends **no file, URL or hash to any third party**, and no API key exists
anywhere in the repository.

### Page alert: one-shot injection, not a resident content script

At the moment a **dangerous** verdict is reached, `chrome.scripting.executeScript()` injects a
self-contained renderer into that one tab. There is **no registered content script** and nothing
runs on any page until a threat occurs.

- `world: "ISOLATED"` — the function cannot reach extension APIs; the page cannot reach it.
- **Closed shadow root** — page CSS cannot restyle the alert; page JS cannot read it.
  *(Verified in a real browser against a page using hostile `* { color: red !important }`.)*
- `pointer-events: none` on the container — the page stays fully usable. **No blocking overlay.**
- Carries only verdict, file name and reason. No URL, no page content, no browsing history.
- `role="alert"`, `aria-live="assertive"`, `dir`/`lang` set for Arabic, motion respects
  `prefers-reduced-motion`.

### Files changed in revision 5

| File | Change |
|---|---|
| `_locales/{en,ar,es,fr}/messages.json` | **New.** 69 keys × 4 languages, Chrome-valid catalogues |
| `lib/i18n.js` | Rewritten as a catalogue resolver; API preserved; `DEFAULT_LANGUAGE` → `en` |
| `lib/threat/provider.js` | **New.** Provider interface, normalization, null + local providers |
| `lib/threat/engine.js` | **New.** Threat state machine with the provider-invariance guarantee |
| `lib/page-alert.js` | **New.** Gating, localized payload, self-contained injected renderer |
| `lib/i18n.test.js`, `lib/localization.test.js`, `lib/threat/engine.test.js`, `lib/page-alert.test.js` | **New.** 109 tests |
| `lib/test-i18n-fixture.js` | **New.** Loads the real shipped catalogues for tests |
| `lib/alert.js` | Localized labels from the catalogue |
| `lib/popup-core.js` | Localized verdict/decision labels; `pageAlerts` in the settings patch |
| `lib/heuristics.js`, `lib/scoring.js` | **Unchanged in 0.2.0** (already carried `params` in 0.1.1) |
| `background.js` | Catalogue loading, threat assessment, page-alert trigger, two new messages |
| `popup.{html,css,js}` | Radar logo, three states, language + page-alert controls |
| `manifest.json` | `0.2.0`, `default_locale`, `__MSG_*__`, optional permissions |
| `icons/radar.svg`, `icons/icon-{16,48,128}.png` | **New/regenerated** Closed Radar identity |
| `README.md`, `HANDOFF.md`, `PROJECT_REPORT.md` | Updated |

### What was deliberately NOT done

No HTTP provider, no API key, no file/URL upload. No `<all_urls>`. No new **required**
permission. No scoring, weight, threshold, timeout or decision-semantics change. No history
migration. No registered content script. No Git commit, push, merge, publish, or release ZIP.

### How to test this revision manually

1. `chrome://extensions` → **Reload**. Open the popup.
2. Confirm **English / LTR** on a fresh profile, with the radar in the **secure** state.
3. Switch to **Arabic** — RTL, Arabic labels; then **Spanish** and **French** — LTR, translated.
   Close and reopen the popup: the choice persists.
4. Seed history from DevTools (`chrome.storage.local`) with a `dangerous` and a `safe` entry;
   confirm badges, decisions and dates render in each language.
5. Download `invoice.pdf.exe` slowly from a local server. Confirm the notification language
   matches the popup, and that button 0 = Cancel and button 1 = Allow.
6. Download a small risky file that finishes inside the 2 s window; confirm the completed-risk
   notification and Delete/Keep labels.
7. Press the buttons; confirm cancel/allow and delete/keep still behave exactly as in 0.1.x.
8. Toggle **Show threat alert on the page** and grant the prompt. Repeat step 5 from a real web
   page. Confirm the vignette + alert box appear **only for a dangerous verdict**, that the page
   stays usable, and that Arabic renders RTL.
9. Deny the permission instead: confirm no alert is injected and the popup explains why.
10. Set sensitivity high, switch language, and confirm sensitivity and the enable toggle survive.

### Verified in a real Chrome session

Chrome for Testing 154.0.8037.92, unpacked, driven over the DevTools Protocol against real
downloads from local HTTP servers (throttled for the held path, instant for the completed path),
plus a local page with deliberately hostile global CSS.

| Check | Result |
|---|---|
| Manifest name / description resolve from `_locales` | pass — *Cyber Guard: Download Threat Protection* |
| Fresh install is English / LTR | pass |
| Arabic / RTL, Spanish / LTR, French / LTR all render translated | pass |
| Language persists across popup reopen | pass |
| Language names in the selector render in the active language | pass (fixed a cold-open ordering bug) |
| History renders in all four languages, canonical values unchanged | pass |
| Secure / analyzing / threat states render distinct colours and animations | pass |
| Threat state only for a `dangerous` verdict | pass |
| `prefers-reduced-motion` guards present and honoured | pass |
| Held-risk notification localized in all four languages | pass |
| Completed-risk notification + Delete/Keep localized (en, ar) | pass |
| `GET_THREAT_STATE` returns threat / verdict / score | pass |
| Page alert suppressed when permission not granted | pass (fail-safe) |
| Page alert renders: vignette + centered box, ⚠️, file, reason, Dismiss | pass (screenshot) |
| Hostile page CSS does not reach the alert | pass (screenshot) |
| Page JS cannot read the alert (closed shadow root) | pass |
| `chrome.*` not visible to the injected function | pass |
| Page remains interactive (`pointer-events: none` container) | pass |
| Arabic alert renders RTL with the icon on the right | pass (screenshot) |

**One real bug was found and fixed during this testing:** the renderer initially appended its
elements to the host's **light DOM** instead of into the shadow root, which left the closed root
empty and would have let page CSS restyle the alert. Caught by screenshot inspection, fixed, and
re-verified.

### Revision 5 results

```
node --test                -> 257 pass / 0 fail / 0 skipped
node --check (22 .js)      -> exit 0 for every file
npx eslint .               -> NOT RUN, no result claimed (see below)
```

**Linting: still not reproducible.** `eslint.config.js` exists, but `eslint` is not declared in
`package.json`, has no lockfile, and is not installed; `npx eslint .` attempts a network install
and does not complete. No lint result is claimed.

---


## 0. Revision 3 — completed-but-risky downloads are no longer discarded

### The reported bug

A very small suspicious file (e.g. `eicar.com`) finishes downloading **inside** the 2-second
analysis window, so the extension can never pause it. The old code treated every terminal state
the same and threw the verdict away:

```
[DG] created #81 ...\eicar.com
[DG] pause requested #81 / paused #81
[DG] analysis started #81 local heuristics / analysis delay #81 2000ms
[DG] external state change #81 state=complete / external cleanup done #81
[DG] heuristic #1 #81 EXECUTABLE_EXTENSION +25
[DG] verdict #81 suspicious score=25
[DG] holding #81 (suspicious) score=25
[DG] analysis result ignored #81 state=complete      <-- verdict discarded
```

Detection worked, but the result was dropped, leaving a flagged file on disk with **no warning
and no record in history**.

### The fix

The post-analysis state check now distinguishes `complete` from `cancelled` / `interrupted` /
missing. A **completed** download with a `suspicious` or `dangerous` verdict is still
actionable, because the bytes are already on disk and `chrome.downloads.removeFile()` can
delete them.

New `notifyCompletedRisk()` in `background.js`:

- Writes a pending session record marked `completedRisk: true`, carrying the verdict, score,
  reasons, filename and host, so `resolveDecision()` can act.
- Raises a distinct persistent notification:
  **Suspicious/Dangerous file already downloaded** — *"This file finished downloading before
  Cyber Guard could pause it."* with **Delete file** / **Keep file** buttons.
- Applies the same 120-second `chrome.alarms` fail-safe timeout.
- Never pretends the finished download can be paused or resumed: no `resume()`, no `cancel()`
  until the user chooses.

New notification text builders in `lib/alert.js`:
`buildCompletedNotificationTitle()`, `buildCompletedNotificationMessage()`.

### Duplicate protection (two independent guards)

1. `completedRiskNotified` — a `Set` in `background.js`. `notifyCompletedRisk()` returns
   `"already-notified"` without creating a second notification or alarm, however many times it
   is called for the same download.
2. `onDownloadsChanged()` now reads the pending record rather than only testing for its
   existence, and returns early when `completedRisk === true`. A repeated state delta can no
   longer tear down a live notification, alarm or pending record while the user is deciding.

Decision-level duplication was already covered by `activeResolutions`, and is now asserted for
the completed-file path too.

### `resolveDecision()` "allow" fix (required for the Keep action)

`resolveDecision(id, "allow", …)` called `chrome.downloads.resume()`. On an **already
completed** download that always throws, which returned `{ok:false}`, **skipped the history
write**, and left the notification, alarm and pending record dangling — so "Keep file" would
have silently done nothing.

The `allow` branch now re-queries the download when `resume()` fails and, if it is already
terminal, treats that as the desired end state and continues to record the decision. This
mirrors the pattern the `cancel` branch already used.

**Behaviour deliberately preserved:** a download that is *still in progress* and genuinely
fails to resume is still an error. It preserves pending state, notification and alarm, and
unlocks `activeResolutions` for a retry. Covered by
`resume failure on a still-paused download still preserves state and retries`.

### Dangerous vs suspicious — fail-safe matrix

| Situation | Dangerous | Suspicious |
|---|---|---|
| User chooses **Delete file** | file removed from disk, entry erased, history recorded | same |
| User chooses **Keep file** | file kept, history recorded | same |
| **Timeout** (no answer, 120 s) | removed (fail safe) | removed (fail safe, matches the existing held-download convention) |
| **Notification cannot be created** | removed (fail safe, mirrors `holdDownload`) | **kept** — never deleted without consent |
| Notification buttons dismissed | removed, cause `notification-closed` | same |

Cancelled, interrupted and not-found downloads are still left completely alone — there is no
completed file to warn about or remove.

### No network access added

No `fetch` or `XMLHttpRequest` was introduced. The manifest still declares **no host
permissions**. All verdicts remain local.

### Regression tests

New `lib/completed_risk.test.js` (16 tests) covering every required scenario:

- suspicious download completes during analysis → flagged (`eicar.com`)
- dangerous download completes during analysis → flagged, score 95
- notification emitted exactly once across repeated state changes and analysis completions
- awaiting-decision record and its notification/alarm survive later state deltas
- duplicate decisions resolve only once; concurrent button press + timeout resolve only once
- **Delete file** → `removeFile` + `erase` + history entry with verdict, cause and hostname
- **Keep file** → succeeds despite impossible `resume()`, file untouched, history recorded
- notification failure → dangerous removed, suspicious kept
- timeout → fail-safe removal with cause `timeout`
- **active paused download unchanged** → still uses the original *Dangerous download*
  notification with **Cancel download** / **Allow anyway**
- active safe download still resumes and clears pending state
- cancelled and interrupted downloads still raise nothing
- `onDownloadsChanged` still tears down an ordinary completed download
- held-download resume-failure semantics still preserved

`lib/analysis_race.test.js` **Test 1** was rewritten. It previously asserted *"NO
notification"* for a dangerous file that completed during analysis — it encoded the reported
bug. It now asserts the corrected behaviour, with a comment explaining the deliberate change.

**Validated by reintroducing the bug** (temporarily forcing the old ignore path):

```
EXIT_WITH_BUG_REINTRODUCED=1
ℹ tests 144   ℹ pass 133   ℹ fail 11
```

11 tests failed, spanning the suspicious, dangerous, duplicate-notification, duplicate-decision,
keep-action and notification-failure scenarios. The injection was then reverted and the suite
returned to 144/144.

---


## 1. Repository and branches

| Item | Link |
|---|---|
| Repository | https://github.com/MohtadySami/cyber-guard-extension |
| Branch under review | https://github.com/MohtadySami/cyber-guard-extension/tree/feature-backend |
| Base branch | https://github.com/MohtadySami/cyber-guard-extension/tree/main |
| Current HEAD (pushed) | `66eea2e` — *Fix popup defects and finalize v0.1.0 release* |
| Code fix commit | `1cca34f` — *Fix duplicate popup messages, hostname display, and unused backend permission* |
| Previous commit | `7890fce` — *Finalize download protection and persistent history* |

- `feature-backend` is pushed and in sync with `origin/feature-backend` at `66eea2e`.
- No reset, rebase, discard, force-push, or history rewrite was performed at any point.
- `66eea2e` added `HANDOFF.md` and two ZIP artifacts **to version control**.

> ### ⚠ Working tree is NOT clean
>
> The revision 3 fix (§0) is **uncommitted** on top of `66eea2e`:
>
> | Path | State |
> |---|---|
> | `background.js` | modified — the fix |
> | `lib/alert.js` | modified — completed-download notification text |
> | `lib/completed_risk.test.js` | **untracked** — new tests |
> | `lib/analysis_race.test.js` | modified — Test 1 rewritten |
> | `README.md` | modified — documents the new behaviour |
> | `HANDOFF.md` | modified — this report |
> | `cyber-guard-v0.1.0.zip` | modified — rebuilt (26,574 B) |
> | `cyber-guard-v0.1.0-SUPERSEDED-925391CF.zip` | **untracked** — new |
>
> **A commit and push are required before PR #1 is meaningful.** As things stand, the remote
> branch, PR #1, and the committed `cyber-guard-v0.1.0.zip` **all still contain the reported
> bug.**

> ### ⚠ The buggy artifact is committed and pushed
>
> `66eea2e` committed the rev-2 ZIP (24,696 B, `925391CF…`) — **the build that contains this
> defect** — and pushed it to `origin/feature-backend`. Anyone fetching the repository today
> can download a broken release. Options, in order of preference:
>
> 1. Commit the rebuild (it overwrites the same path with the fixed 26,574 B build), push, and
>    `git rm --cached` the superseded artifacts so only the correct ZIP is distributed.
> 2. Leave them tracked but rely on this report.
>
> Either way, confirm the ZIP a reviewer would actually download hashes to `CC9EFF42…` before
> treating the branch as releasable. I did not delete or untrack anything — that needs your
> authorization.

## 2. Pull request status

| Item | Value |
|---|---|
| PR | **#1 — OPEN, not merged** |
| URL | https://github.com/MohtadySami/cyber-guard-extension/pull/1 |
| Base ← head | `main` ← `feature-backend` |
| Head commit | `66eea2e` — **does not contain the revision 3 fix** |

**Awaiting approval before merge.**

## 3. Defects fixed in this revision

### 3.1 Duplicate message dispatch (popup.js)

`sendMessage()` called `chrome.runtime.sendMessage` **twice** per message: once without a
callback purely to "check whether it returns a promise", then again with the callback. Every
`SET_SETTINGS` and `CLEAR_HISTORY` therefore executed twice.

**Fix:** extracted to `lib/popup-core.js`. It performs exactly one call and reads
`runtime.lastError` inside the callback, which also removes the "Unchecked runtime.lastError"
console noise. All error handling and return behaviour is preserved
(`{ok:false,error:"runtime unavailable"}`, `{ok:false,error:"invalid response"}`,
normalised thrown errors, and a settle-once guard).

### 3.2 History hostname never displayed (popup.js + lib/history.js)

`lib/history.js` normalises entries to a **`hostname`** key, but `popup.js` read
**`entry.host`**, which is always `undefined` — so the host column in the popup history list
was silently blank.

**Fix:** `toHistoryRow()` in `lib/popup-core.js` reads the normalised `hostname` schema and
still accepts a legacy `host` key so entries written by earlier builds keep rendering.
Malformed timestamps are skipped rather than throwing.

### 3.3 Unused backend feature removed

The manifest declared `host_permissions: ["http://127.0.0.1:7471/*"]` and the popup showed
an Arabic "deep analysis (Backend)" toggle, but **no `fetch` or `XMLHttpRequest` existed
anywhere in the codebase** — the backend was never implemented.

**Fix — removed, not implemented.** No network call was added to justify the permission.

- `manifest.json`: `host_permissions` removed entirely.
- `popup.html`: backend toggle and backend URL field removed; now loads `popup.js` as a
  module (`<script type="module">`) so it can import the shared helpers.
- `popup.js`: `useBackendToggle`, `backendUrlInput`, `isValidBackendUrl()`, and the
  `backendUrlError` string removed.
- `popup.css`: the now-unused `.setting-row.vertical` rule removed.
- `background.js`: `useBackend` and `backendUrl` removed from `DEFAULT_SETTINGS`. A
  `RETIRED_SETTINGS_KEYS` list strips them on read *and* write, so keys left in
  `chrome.storage.local` by earlier builds are cleaned up and cannot be reintroduced.

All local heuristics are untouched and still fully functional.

### 3.4 Lint findings

`npx eslint .` previously exited 1 with 3 findings. All resolved:

| File | Finding | Resolution |
|---|---|---|
| `popup.js` | `saveButtonDisabled` assigned but never used | Removed (dead variable) |
| `popup.js` | caught error `'e'` never used | Removed; timestamp parsing is now guarded by `Number.isFinite` |
| `lib/scoring.test.js` | `SCORING_CONSTANTS` imported but never used | Now exercised by two new tests asserting every sensitivity threshold and the hard-signal list |

(Original line numbers are omitted: `popup.js` was later rewritten to delegate to
`lib/popup-core.js`, so `popup.js:13` / `popup.js:138` no longer exist.)

## 4. Tests and lint — actual results

Revision 4 results (Node.js v26.7.0):

```
node --test                  -> 181 pass / 0 fail / 0 skipped
node --check <all 20 .js>    -> exit 0 for every file
npx eslint .                 -> NOT RUN, no result claimed (see below)
```

Test count: 100 (original) → 128 (revision 2) → 144 (revision 3) → **181 (revision 4)**.

**Revision 3 results are retained below unchanged.** Note that the ESLint lines quoted there
were produced on the audit machine, where the dependencies happened to be present; they are
**not reproducible from this checkout** and are not re-verified here.

### Lint — no result claimed for revision 4

`eslint.config.js` is present, but `eslint` itself is not declared in `package.json`, has no
lockfile, and is not installed in `node_modules` (only the `@eslint` and `globals` config
packages are). `npx eslint .` attempts a network install and does not complete. **No lint
result is claimed for revision 4.** Installing ESLint and pinning it in `package.json` remains
open work.

### Localization regression tests added

| File | Guards |
|---|---|
| `lib/i18n.test.js` | **New in revision 4 (17 tests).** Arabic default, normalization and every fallback path, key resolution, missing-key fallback, interpolation, RTL/LTR, locales, reason localization by code, complete reason-code coverage, notification button labels and index order |
| `lib/localization.test.js` | **New in revision 4 (20 tests).** Settings persistence and invalid-value repair, language switches preserving other settings, localized held/completed notification titles, messages, reasons and buttons, history in both languages, and — critically — that language does **not** change scores, thresholds, or heuristic weights |

### Regression tests added

| File | Guards |
|---|---|
| `lib/completed_risk.test.js` | **New in revision 3 (16 tests).** The completed-but-risky download path — see §0 |
| `lib/analysis_race.test.js` | **Test 1 rewritten** in revision 3; it previously asserted the buggy "no notification" behaviour |
| `lib/popup-core.test.js` | Duplicate-send (single call, settings saved once, history cleared once, sequential and concurrent counts), preserved error handling, **hostname round-trip through the real `lib/history.js` normaliser**, legacy `host` key, malformed-field tolerance, verdict badges, and absence of backend keys in the settings patch |
| `lib/settings.test.js` | Retired backend keys absent from defaults, stripped on read, stripped from storage on write, and impossible to reintroduce via a partial update |

**These tests were validated by reintroducing each original defect and confirming they fail:**

```
# revision 3 — old ignore path forced back on
EXIT_WITH_BUG_REINTRODUCED=1
ℹ tests 144   ℹ pass 133   ℹ fail 11
AssertionError: Completed risky file is flagged
AssertionError: notification must be raised
AssertionError: pending record must survive
AssertionError: exactly one decision wins
AssertionError: keep must succeed even though resume is impossible
AssertionError: dangerous file removed when unnotifyable

# revision 2 — duplicate send + hostname regressions
AssertionError: must not send the message twice
AssertionError: hostname missing from meta line: "score:95 | 11/15/2023, 1:13:20 AM"
AssertionError: hostname missing after normalise+render: "score:55 | 10/2/2026, 5:33:10 PM"
EXITCODE_WITH_BUGS_INJECTED=1
```

Each injection was then reverted and the suite returned to green.

## 5. Release package

Rebuilt for revision 4.

**Version decision: 0.1.1, not 0.1.0.** Language selection is a new user-facing feature with
a new persisted setting. Shipping it inside the already-audited 0.1.0 artifact would
invalidate that audit's recorded hash and make the released bundle no longer match the
documented build, so the version was bumped and a new package produced.

| Item | Value |
|---|---|
| Path | `C:\Users\User\cyber-guard-extension\cyber-guard-v0.1.1.zip` |
| Size | **33,307 bytes** |
| Entries | 14, `manifest.json` at ZIP root, no unexpected directories |
| Every packaged file vs final source | **14/14 byte-for-byte MATCH** |
| Forbidden content (tests, dev deps, docs, secrets) | none |
| `fetch` / `XMLHttpRequest` / `WebSocket` / `host_permissions` in package | **none** |

### NEW release hash (revision 4 / v0.1.1)

```
508A72DBEECA59D105746FD7C14A32312D971569B3C6898F16CD6D54B37C4521
```

### Superseded hashes — kept for reference only, do NOT upload

| Revision | File | Size | SHA-256 | Tracked? |
|---|---|---|---|---|
| rev 3 | `cyber-guard-v0.1.0-SUPERSEDED-CC9EFF42.zip` | 26,574 B | `CC9EFF42898513294F139D6652A60593033C00394DD6CBFD19928D0699A99C65` | untracked; byte-identical to the rev 3 build at `2564bb9` |
| rev 2 | `cyber-guard-v0.1.0-SUPERSEDED-925391CF.zip` | 24,696 B | `925391CF038430DCA617884EA5FE97AC34DBDFEAA336BD54ECEB72B8A3D219B3` | untracked |
| rev 1 | `cyber-guard-v0.1.0-SUPERSEDED-430F8F6E.zip` | 23,015 B | `430F8F6EBBAE8BC7DEBC441C6EA698B96058DAAAC2A6E2FCC43DCF1E6EA1CDB4` | **committed at `66eea2e`** |

**The rev 2 artifact is the one that reproduces the reported bug** — it discards a risky
verdict for a completed download. Neither superseded file was overwritten or deleted; both are
preserved byte-identical for audit. Note that `cyber-guard-v0.1.0.zip` at `66eea2e` is the
**same defective rev 2 build**; the fixed build exists only in the working tree.

### Packaged contents

```
manifest.json        background.js     popup.html   popup.css   popup.js
lib/alert.js         lib/heuristics.js lib/history.js
lib/i18n.js          lib/popup-core.js lib/scoring.js
icons/icon-16.png    icons/icon-48.png icons/icon-128.png
```

Walking the ES import closure from both entry points (`background.js`, `popup.js`) reaches all
**8** packaged JS modules with **no unresolved imports** and **no packaged-but-unreachable**
JS. `lib/i18n.js` is a genuine runtime dependency of `background.js`, `popup.js`,
`lib/alert.js`, and `lib/popup-core.js`, so it must ship in the package.

Verification also extracted the ZIP to a temp directory and confirmed the packaged
`manifest.json` parses (`host_permissions` absent), every packaged `.js` passes
`node --check`, all `popup.html` references resolve, and the completed-file notification
strings are present in `lib/alert.js`.

## 6. Manifest and permission review

| Item | Value |
|---|---|
| `manifest_version` | 3 |
| `version` | 0.1.0 |
| Background | `background.js`, `type: module` |
| Permissions | `downloads`, `storage`, `notifications`, `alarms` |
| Host permissions | **none** |

Each permission is justified by code that actually uses it. The remaining concern is
enforcement, not declaration:

- **`downloads`** — `chrome.downloads.pause/resume/cancel/removeFile/erase`. Required.
- **`storage`** — `chrome.storage.local` (settings, decision history) and
  `chrome.storage.session` (per-download recovery records). Required.
- **`notifications`** — the Allow / Cancel prompt for a paused download, and the Delete file /
  Keep file prompt for a download that finished before it could be paused. Required. Note the
  extension creates notifications with `requireInteraction: true`; reviewers sometimes
  question persistent notifications, so the store listing should explain the user-facing
  reason: the user must be able to act on a risky download after looking away from the screen,
  including when the file is already on disk.
- **`alarms`** — the 120-second fail-safe timeout for both the paused and the
  already-completed risky download. Required.

`minimum_chrome_version` is `114`, which is the minimum that provides
`chrome.storage.session`. That is correct and not a listing problem.

**I cannot and do not guarantee store approval.** Remaining listing work is in §8.

## 7. Remaining issues

### Not fixed — out of scope for a release blocker

1. **Redirect tracking is unimplemented.** `buildContext()` hardcodes `redirectChain: []`, so
   `checkLongRedirectChain` and `checkLookalikeDomain` never fire. The corresponding
   `TODO(step 3)` was deliberately kept because the work is genuinely incomplete.
2. **2-second analysis delay retained** (`DEBUG_ANALYSIS_DELAY_MS`) deliberately, to match
   the "pauses downloads briefly" product behaviour.
3. **`trustedDomains` and `autoResumeSafe`** are supported by the settings engine but have no
   UI. They are documented as such in the README.
4. **Documentation drift fixed** — `README.md` was rewritten to describe the real
   implementation, the `analyzeDownload` JSDoc no longer claims "no security rules", the
   "Step 1 placeholder" log line now reads "local heuristics", and the completed
   `TODO(step 2/4/5)` markers were removed.
5. **`onDownloadsChanged()` now reads the pending record** instead of only testing for its
   existence, to honour `completedRisk`. Ordinary (non-`completedRisk`) downloads behave
   exactly as before, and that is asserted by a test.

### Changed behaviour a reviewer should confirm

The revision 3 fix is a **deliberate behaviour change**, not a pure refactor: a download that
completes during analysis with a `suspicious`/`dangerous` verdict now produces a notification
and a history entry where it previously produced neither. Any test, doc or expectation that
asserted "no notification for a completed risky download" is now wrong. `lib/analysis_race.test.js`
Test 1 was such a test and was rewritten deliberately.

## 8. Manual steps remaining

1. **Commit and push the revision 3 fix.** The fix, its tests, the README update and the
   rebuilt ZIP are all uncommitted. Until this happens, PR #1 and the repository's committed
   ZIP both still ship the reported bug.
2. **Decide what to do with the committed buggy ZIP** (see §1). `cyber-guard-v0.1.0.zip` at
   `66eea2e` is the defective 24,696-byte build; it is currently downloadable from the branch.
   All three ZIPs are tracked in version control — consider `git rm --cached` on the two
   `SUPERSEDED-*.zip` files and `.gitignore` for `*.zip` so only the correct artifact ships.
3. **Review and merge PR #1** — not merged, awaiting approval. Do this only *after* step 1, and
   re-check the PR diff to confirm the revision 3 changes are present.
4. **Verify the completed-download fix in a real Chrome.** This is the highest-priority manual
   step, because the new code path has **never run outside the unit tests**. Load unpacked and
   run README manual test **#7**: download a tiny file with a risky name such as `eicar.com`
   over `http://` so it completes inside the 2s analysis window. Expected: a **Suspicious file
   already downloaded** notification with **Delete file** / **Keep file**, no resume, no
   cancel, and one history entry. Then confirm **Delete file** actually removes the file from
   disk — `chrome.downloads.removeFile()` behaviour on a completed download is the one
   mechanism this fix depends on that the mocks cannot prove.
5. **Decide whether to re-verify the popup in Chrome.** Load unpacked and run the README manual
   tests, paying particular attention to the popup (module script loading, settings round-trip,
   and hostname display in the history list), since those paths are unit tested but not yet
   exercised in a real browser.
6. **Publish the store listing** — see §9.

## 9. Chrome Web Store upload steps (partner's own account)

Ownership is not transferable, so the partner must create and own the listing with their own
Chrome Web Store developer account. Budget the one-time **$5** developer registration fee.

1. Sign in at https://chrome.google.com/webstore/devconsole with the partner's Google account.
2. Complete the one-time **$5 developer registration**.
3. **Add new item → Upload the first package**.
4. Upload `cyber-guard-v0.1.0.zip` — do not repackage, rename, or re-zip it.
   - Expected size: **26,574 bytes**
   - Expected SHA-256: **`CC9EFF42898513294F139D6652A60593033C00394DD6CBFD19928D0699A99C65`**
   - Reject any file whose hash does not match. Both `SUPERSEDED-*.zip` artifacts contain the
     reported defect and must not be uploaded.
5. Listing details:
   - **Name:** Cyber Guard
   - **Category:** Privacy
   - **Language:** Arabic (the UI is Arabic/RTL); add English if wanted
   - **Description:** state that downloads are briefly paused for a local safety check, that
     risky files prompt Allow / Cancel, and that **all analysis is local and nothing is
     uploaded**
6. **Permission justifications** (the store will ask):

   | Permission | Justification text |
   |---|---|
   | `downloads` | Pauses, resumes, cancels and removes individual downloads so a safety check can run before a file is saved |
   | `storage` | Saves your settings and your local decision history on the device |
   | `notifications` | Prompts you to allow or cancel a download that scored as risky |
   | `alarms` | Applies a 2-minute timeout that cancels a risky download you did not respond to |

   There are **no host permissions** to justify this release, which removes the most common
   cause of a permissions-related rejection.
7. Upload the 128×128 store icon and screenshots — the listing form needs its own copies.
8. Set visibility (**Public**, or **Unlisted** for a limited release).
9. Submit for review. First-time submissions commonly take several days to a few weeks.

---

## Completed vs. requires authorization

**Completed:** git verification · PR #1 created and updated · duplicate-send fix · hostname
display fix · backend feature removal · all eslint findings resolved · README rewritten ·
**completed-but-risky download fix + `resolveDecision` keep-action fix** · regression tests added
and validated against reintroduced defects · full test/lint/syntax runs · release ZIP rebuilt
and verified · this report.

**Deliberately not done, per your constraints:** merging PR #1 · publishing to the Chrome Web
Store · force-push · history rewrite · deleting or discarding any file.

**Requires your authorization:** committing and pushing the revision 3 fix · any
untracking/deletion of the committed ZIP artifacts · merging PR #1 · publishing to the Chrome
Web Store · any change to the analysis delay or the redirect-tracking feature.

I did **not** commit, push, merge, publish, delete, untrack or discard anything while preparing
this report. Every change described above is left in the working tree for your review.

### Known limits of this report

- `chrome.downloads.removeFile()` on a **completed** download is the load-bearing assumption
  of the delete action. The mocks assert the call is issued and succeeds; it has not been
  confirmed against real Chrome. README manual test #7 covers this.
- The new completed-download path has never been exercised in a real browser, only in unit
  tests.
- The popup module-script load strategy remains unverified in a real browser.
- Store approval cannot be guaranteed from static review. The remaining soft spot is
  `requireInteraction: true` notifications.
