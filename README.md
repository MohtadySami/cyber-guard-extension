# Cyber Guard Extension

Step 1 proves the Manifest V3 service-worker plumbing: each active download is paused,
waits two seconds for a placeholder analysis, and is resumed in a `finally` block. No
security detection, network requests, notifications, or UI exist yet.

## Permissions

- `downloads`: reads download metadata and pauses or resumes individual downloads.
- `storage`: saves settings in `chrome.storage.local` and isolated per-download recovery
  records in `chrome.storage.session`.

`manifest.json` is strict JSON, so permission explanations live here rather than as
comments in the manifest.

## Load Unpacked

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose this project folder:
   `C:\Users\User\cyber-guard-extension`.
4. Click the **service worker** link on the Cyber Guard card to open its DevTools console.
   Filter the console for `[DG]` to view the lifecycle logs.

## Manual Tests

1. **Extension loads cleanly:** Reload the unpacked extension on `chrome://extensions`.
   Expected: no errors; only `downloads` and `storage` appear in its permissions.
2. **Normal download:** Download any ordinary file. Expected logs: `created`, `pending
   marked`, `pause requested`, `paused`, `analysis started`, `analysis finished`, `resume
   requested`, `resumed`, and `pending cleared`. The file completes after about two seconds.
3. **Instant download race:** Download a very small file. Expected: either the normal flow or
   `too late to pause` / `skipped (already finished)`; no crash and no pending record remains.
4. **Forced analysis error:** Change `DEBUG_FORCE_ERROR` in `background.js` to `true`, reload
   the extension, then download a file. Expected: `analysis error` and `analysis fallback`,
   followed by `resumed` and `pending cleared`. Change it back to `false` afterward.
5. **Worker restart recovery:** Start a sufficiently large download, wait until it logs
   `paused`, then stop the extension service worker from its DevTools/Application tools. Wake
   it with another download or by reopening the extension worker. Expected: the startup
   recovery logs resume the originally paused download and clear its `pending:<id>` record.
6. **Concurrent downloads:** Start three downloads before the first analysis completes.
   Expected: each download ID has separate `[DG]` logs and all three finish.
7. **Disabled setting:** In the service-worker console, run:

   ```js
   await chrome.runtime.sendMessage({
     type: "SET_SETTINGS",
     settings: { enabled: false },
   });
   ```

   Download a file. Expected: it is untouched and logs `skipped (disabled)`. Re-enable with
   the same command using `enabled: true`.
8. **Manual cancellation:** Start a download and cancel it during the two-second pause.
   Expected: `resume failed` is logged and handled; no unhandled error or pending record
   remains.

To inspect recovery state while testing, run `await chrome.storage.session.get(null)` in the
service-worker console. After each settled download it should not contain any `pending:<id>` key.
