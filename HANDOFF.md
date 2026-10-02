# Cyber Guard v0.1.0 — Partner Handoff Report

**Prepared:** 2026-10-02
**Revision:** 2 — release candidate rebuilt after defect fixes
**Status:** PR #1 open, not merged. Nothing published to the Chrome Web Store.

---

## 1. Repository and branches

| Item | Link |
|---|---|
| Repository | https://github.com/MohtadySami/cyber-guard-extension |
| Branch under review | https://github.com/MohtadySami/cyber-guard-extension/tree/feature-backend |
| Base branch | https://github.com/MohtadySami/cyber-guard-extension/tree/main |
| Fix commit | `1cca34f` — Fix duplicate popup messages, hostname display, and unused backend permission |
| Previous commit | `7890fce` — Finalize download protection and persistent history |

- `feature-backend` is pushed and in sync with `origin/feature-backend`.
- Working tree is clean. No reset, rebase, discard, force-push, or history rewrite was performed.

## 2. Pull request status

| Item | Value |
|---|---|
| PR | **#1 — OPEN, not merged** |
| URL | https://github.com/MohtadySami/cyber-guard-extension/pull/1 |
| Base ← head | `main` ← `feature-backend` |
| Head commit | `1cca34f` |

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
| `popup.js:13` | `saveButtonDisabled` assigned but never used | Removed (dead variable) |
| `popup.js:138` | caught error `'e'` never used | Removed; timestamp parsing is now guarded by `Number.isFinite` |
| `lib/scoring.test.js:5` | `SCORING_CONSTANTS` imported but never used | Now exercised by two new tests asserting every sensitivity threshold and the hard-signal list |

## 4. Tests and lint — actual results

```
node --test                  -> 128 pass / 0 fail / 0 skipped   (exit 0)
node --check background.js   -> exit 0
node --check popup.js        -> exit 0
node --check lib/popup-core.js -> exit 0   (+ alert, heuristics, history, scoring all exit 0)
npx eslint .                 -> exit 0, no findings
npx eslint background.js     -> exit 0
```

Test count rose from **100 to 128**.

### Regression tests added

| File | Guards |
|---|---|
| `lib/popup-core.test.js` | Duplicate-send (single call, settings saved once, history cleared once, sequential and concurrent counts), preserved error handling, **hostname round-trip through the real `lib/history.js` normaliser**, legacy `host` key, malformed-field tolerance, verdict badges, and absence of backend keys in the settings patch |
| `lib/settings.test.js` | Retired backend keys absent from defaults, stripped on read, stripped from storage on write, and impossible to reintroduce via a partial update |

**These tests were validated by reintroducing each original defect and confirming they fail:**

```
AssertionError: must not send the message twice
AssertionError: hostname missing from meta line: "score:95 | 11/15/2023, 1:13:20 AM"
AssertionError: hostname missing after normalise+render: "score:55 | 10/2/2026, 5:33:10 PM"
EXITCODE_WITH_BUGS_INJECTED=1
```

Both defects were then reverted and the full suite returned to 128/128.

## 5. Release package

| Item | Value |
|---|---|
| Path | `C:\Users\User\cyber-guard-extension\cyber-guard-v0.1.0.zip` |
| Size | 24,696 bytes |
| Entries | 13, `manifest.json` at ZIP root, no unexpected directories |
| Every packaged file vs final source | **13/13 byte-for-byte MATCH** |
| Forbidden content (tests, dev deps, docs, secrets) | none |

### NEW release hash

```
925391CF038430DCA617884EA5FE97AC34DBDFEAA336BD54ECEB72B8A3D219B3
```

### Previous (superseded) release hash — kept for reference only

```
430F8F6EBBAE8BC7DEBC441C6EA698B96058DAAAC2A6E2FCC43DCF1E6EA1CDB4
```

The old artifact was **not** overwritten. It is preserved alongside the new one as
`cyber-guard-v0.1.0-SUPERSEDED-430F8F6E.zip`. Do not upload the superseded file.

### Packaged contents

```
manifest.json        background.js     popup.html   popup.css   popup.js
lib/alert.js         lib/heuristics.js lib/history.js
lib/popup-core.js    lib/scoring.js
icons/icon-16.png    icons/icon-48.png icons/icon-128.png
```

`lib/popup-core.js` is new and is a genuine runtime dependency of `popup.js`; its presence in
the package was confirmed by walking the import closure.

Verification also extracted the ZIP to a temp directory and confirmed the packaged
`manifest.json` parses, every packaged `.js` passes `node --check`, and all `popup.html`
references resolve.

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
- **`notifications`** — the Allow / Cancel prompt. Required. Note the extension creates
  notifications with `requireInteraction: true`; reviewers sometimes question persistent
  notifications, so the store listing should explain the user-facing reason.
- **`alarms`** — the 120-second fail-safe timeout. Required.

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

## 8. Manual steps remaining

1. **Review and merge PR #1** — not merged, awaiting approval.
2. **Optionally add the two release ZIPs to `.gitignore`.** Both are currently untracked and
   were intentionally left out of the commit.
3. **Decide whether to re-verify in Chrome.** Load unpacked and run the README manual tests,
   paying particular attention to the popup (module script loading, settings round-trip, and
   hostname display in the history list), since those paths are unit tested but not yet
   exercised in a real browser.
4. **Publish the store listing** — see §9.

## 9. Chrome Web Store upload steps (partner's own account)

Ownership is not transferable, so the partner must create and own the listing with their own
Chrome Web Store developer account. Budget the one-time **$5** developer registration fee.

1. Sign in at https://chrome.google.com/webstore/devconsole with the partner's Google account.
2. Complete the one-time **$5 developer registration**.
3. **Add new item → Upload the first package**.
4. Upload `cyber-guard-v0.1.0.zip` — do not repackage, rename, or re-zip it.
   - Expected size: **24,696 bytes**
   - Expected SHA-256: **`925391CF038430DCA617884EA5FE97AC34DBDFEAA336BD54ECEB72B8A3D219B3`**
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

**Completed:** git verification and push · PR #1 updated · duplicate-send fix · hostname
display fix · backend feature removal · all eslint findings resolved · README rewritten ·
regression tests added and validated against reintroduced defects · full test/lint/syntax runs ·
ZIP rebuilt and verified · this report.

**Requires your authorization:** merging PR #1 · publishing to the Chrome Web Store · any
change to the analysis delay or the redirect-tracking feature.
