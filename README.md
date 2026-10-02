# Cyber Guard Extension

A Manifest V3 Chrome extension that briefly pauses each download, scores it with local
heuristics, and asks you what to do when the score looks risky. **All analysis happens
locally in the browser — no network request is made and no data is uploaded.**

## How it works

1. A download starts. The service worker saves a recovery record in
   `chrome.storage.session`, then pauses the download.
2. Local heuristics inspect the file name and source URL. Each hit contributes points.
3. The total score is mapped to a verdict using the configured sensitivity threshold:

   | Verdict | Low sensitivity | Medium (default) | High |
   |---|---|---|---|
   | `safe` | 0–39 | 0–29 | 0–19 |
   | `suspicious` | 40–69 | 30–59 | 20–49 |
   | `dangerous` | 70+ | 60+ | 50+ |

4. `safe` downloads resume immediately. `suspicious` and `dangerous` downloads stay paused
   and raise a notification with **Cancel download** / **Allow anyway** buttons.
5. If you do not answer within 120 seconds, a `chrome.alarms` timeout fails safe and
   **cancels** the download.
6. Every resolved decision (including the cause: `user-button`, `timeout`,
   `notification-closed`, `notification-failed`, `hold-error`) is recorded in persistent
   history and shown in the popup.

### Downloads that finish before the check

A very small file can finish downloading inside the analysis window, before Cyber Guard can
pause it. If its verdict is `suspicious` or `dangerous`, the extension does **not** discard
the result. Because the file is already on disk, `chrome.downloads.removeFile()` can still
delete it, so the extension raises a distinct notification:

> **Suspicious file already downloaded** / **Dangerous file already downloaded**
> This file finished downloading before Cyber Guard could pause it.
> …Choose **Delete file** to remove it from disk, or **Keep file** to allow it.

The same 120-second fail-safe alarm applies, and the outcome is recorded in history with the
normal causes. The completed-file notification is emitted at most once per download, and a
later state change will not tear it down while you are deciding.

- **Delete file** removes the file from disk (`removeFile`) and erases the download entry.
- **Keep file** leaves it in place and just records the decision.

Cancelled, interrupted and not-found downloads are still left alone, because there is no
completed file to warn about or remove.

If the notification cannot be created at all, the extension fails safe: a **dangerous** file
is deleted, while a merely **suspicious** one is kept rather than deleted without consent.

### Heuristics

`lib/heuristics.js` contributes scored signals including double extensions
(`invoice.pdf.exe`), executable extensions, script extensions, container/archive
extensions, macro documents, RTLO characters, trailing spaces or dots, MIME mismatch,
insecure HTTP, IP-literal hosts, suspicious TLDs, and punycode hosts.

`RTLO_CHARACTER`, `DOUBLE_EXTENSION`, and `MIME_MISMATCH` are treated as hard signals:
they override the trusted-domain exemption, so a trusted host sending a double extension
is still flagged.

## Permissions

| Permission | Why it is used |
|---|---|
| `downloads` | Pause, resume, cancel, and erase individual downloads |
| `storage` | Save settings and decision history in `chrome.storage.local`; keep per-download recovery records in `chrome.storage.session` |
| `notifications` | Show the Allow / Cancel prompt for risky downloads |
| `alarms` | 120-second timeout that cancels an unanswered prompt |

There are **no host permissions**. Cyber Guard does not contact any server.

`manifest.json` is strict JSON, so permission explanations live here rather than as
comments in the manifest.

## Settings

Available in the popup:

- **Enable protection** (`enabled`, default `true`)
- **Detection sensitivity** (`sensitivity`: `low` / `medium` / `high`, default `medium`)
- **Clear history** (wipes the stored decision log)

`trustedDomains` and `autoResumeSafe` are supported by the settings engine but have no
user interface yet.

## Project layout

```
manifest.json          Extension manifest (MV3)
background.js          Service worker: download lifecycle, hold/resume, timeout, recovery
popup.html / .css / .js  Popup UI
lib/heuristics.js      Signal detection
lib/scoring.js         Score aggregation and verdict thresholds
lib/alert.js           Notification title and message builders (held and completed-file variants)
lib/history.js         Persistent decision history (serialized write queue, capped at 100)
lib/popup-core.js      DOM-free popup helpers (single-send messaging, history row rendering)
```

## Load Unpacked

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose this project folder:
   `C:\Users\User\cyber-guard-extension`.
4. Click the **service worker** link on the Cyber Guard card to open its DevTools console.
   Filter the console for `[DG]` to view the lifecycle logs.

## Tests and linting

```bash
npm test              # node --test
node --check background.js
npx eslint .
```

## Manual tests

1. **Extension loads cleanly:** Reload the unpacked extension on `chrome://extensions`.
   Expected: no errors, and only the four permissions above are requested.
2. **Safe download:** Download an ordinary file. Expected logs: `created`, `pending marked`,
   `pause requested`, `paused`, `analysis started`, `analysis finished`, `resume requested`,
   `resumed`, `pending cleared`. The file completes after about two seconds.
3. **Risky download:** Download a file named like `invoice.pdf.exe` from an `http://` URL.
   Expected: `verdict ... dangerous`, a notification with both buttons, and an `alarm set`
   log line. Nothing is resumed until you choose.
4. **Timeout:** Ignore the notification for more than two minutes. Expected: the download is
   cancelled and a `cancel` entry with cause `timeout` appears in the popup history.
5. **Instant download race:** Download a very small file. Expected: either the normal flow or
   `too late to pause` / `skipped (already finished)`; no crash and no pending record remains.
6. **External cancellation:** Start a download and cancel it during the pause. Expected:
   `external state change` then `external cleanup done`; no notification or alarm is left behind.
7. **File too small to pause (the reported bug):** Download a tiny file with a risky name, such
   as `eicar.com` over `http://`. It finishes inside the 2s analysis window. Expected:
   `download completed before analysis finished`, then a **Suspicious file already downloaded**
   notification with **Delete file** / **Keep file**, and an `alarm set` line. Nothing is
   resumed or cancelled. Choose **Delete file** and confirm the file is gone from disk and the
   entry appears in the popup history; repeat and choose **Keep file** to confirm it stays.
8. **No duplicate notification:** With the completed-file notification still on screen, wait for
   further download activity. Only one notification should exist and only one history entry
   should be written for that download.
9. **Concurrent downloads:** Start three downloads before the first analysis completes.
   Expected: each download ID has separate `[DG]` logs and all three finish.
10. **Worker restart recovery:** Start a sufficiently large download, wait until it logs
   `paused`, then stop the service worker from its DevTools/Application tools. Wake it with
   another download. Expected: startup recovery resumes the paused download and clears its
   `pending:<id>` record. A download that was already *held*, or that finished and is awaiting
   a decision, is left alone so its live notification and alarm keep working.
11. **Disabled setting:** In the service-worker console, run:

   ```js
   await chrome.runtime.sendMessage({
     type: "SET_SETTINGS",
     settings: { enabled: false },
   });
   ```

   Download a file. Expected: it is untouched and logs `skipped (disabled)`. Re-enable with
   the same command using `enabled: true`.

To inspect recovery state while testing, run `await chrome.storage.session.get(null)` in the
service-worker console. After each settled download it should not contain any `pending:<id>` key.

## Known limitations

- **Redirect tracking is not implemented.** `buildContext()` supplies an empty
  `redirectChain`, so the redirect-chain and lookalike-domain heuristics never fire.
- **Analysis is intentionally delayed by 2 seconds** (`DEBUG_ANALYSIS_DELAY_MS`) so the
  download is visibly paused while the heuristics run.
- **Trusted domains have no UI** and must be set through the service-worker console.
- **No backend analysis.** A backend toggle and a `http://127.0.0.1:7471/*` host permission
  existed in earlier builds but were never implemented; both were removed for 0.1.0 rather
  than shipping an unused permission.
