# Inspection liveness check failure details

## Using

In Inspection History, click Failure Details (N) in the Liveness Result column to see the account ID, email, failure type, recorded time, and reason for every account whose liveness check failed in that task. Both the old and new UIs support it, 20 items per page; it refreshes every 5 seconds while open and can also be refreshed manually.

- Failure types include liveness check failed, account deactivated, enqueue rejected, and execution error.
- Details store the account email and failure reason as they were at the time, independent of the current account status or liveness logs that may be overwritten; later liveness checks, account deletion, and service restarts do not rewrite saved details.
- Plan-only failures are not counted as liveness check failures and do not appear in this list.
- Older tasks have no saved details, so the UI says they cannot be restored; the current account error is not used to stand in for a historical error.

## Implementation and consistency

- `account_inspection_failures` is a separate table keyed by `(inspection_id, account_id)`; queries are paginated per task, and the failure list is not put into the stats JSON.
- Failure details are written in the same transaction as the corresponding stats; if the write fails, the in-memory counters are restored, so the task finally block cannot save a failure count without details on its own.
- Terminated tasks and stale workers cannot write details; duplicate details for the same account in the same task are not inserted twice.
- API: `GET /api/accounts/inspections/{id}/failures?page=1`, which reuses login authentication; an invalid page number returns 400 and a missing task returns 404. Returns the current page, the total, the task summary, and `details_available`.
- The full login result, AT, cookies, or BrowserSession objects are not stored, only the selected failure fields; the reason is stored up to 2000 characters.
- The frontend escapes the email, reason, and unknown statuses; responses from a previous task are isolated when switching tasks, and loading can be retried after a timeout.

## Verification (2026-10-18)

- Full unittest run: 389 tests passed (22.331 s).
- Inspection-specific: 72 tests passed in 3 consecutive rounds (7.717 / 6.445 / 6.884 s); the mixed-concurrency test additionally checks that each task detail count equals the saved failure count.
- Covers enqueue rejection, exceptions, deactivated accounts, history snapshots unaffected by account changes/deletion, restart retention, transaction rollback, terminal-state protection, pagination, authentication, legacy records, and isolation of plan failures.
- Node UI: stale-response isolation on task switch, pagination, HTML escaping, legacy-task notice, empty state, and request timeout with retry all passed.
- Chrome mock API rendering: old and new templates on desktop/mobile, nested modal Escape, page bounds, and escaping passed.
- compileall, `git diff --check` passed; no real login / code retrieval / plan network requests were run.

## Bug and UI adaptation review (2026-10-18)

- First reproduced with real Chrome: refreshing in place rebuilt the table, which sent the mobile horizontal reading position back to the far left. The history and failure-details rendering logic is now unified: unchanged content is not rebuilt; when data changes, the in-page horizontal and vertical scroll positions and the keyboard focus in the table area are preserved; paging resets the reading position.
- Long emails wrap so a single column cannot grow without bound; on mobile a hint tells users to swipe left and right to see the full reason, and the scroll area can be focused by keyboard.
- Opening another task immediately clears the old archive notice and disables the old pagination buttons, so the previous task information is not shown while loading.
- Added a repeatable browser regression script: `.venv/bin/python tests/browser_account_inspection_check.py`. It needs the Playwright Python package and a local Chrome; screenshots are saved in a temporary directory.
- This round full unittest run: 389 tests passed (44.789 s); inspection-specific: 72 tests passed (8.315 s). The database/disk faults in the logs are injected test scenarios, and the test result is OK.
- Node UI The regression passed, with new checks for no rebuild when unchanged in place, preserved scroll on change, reset on paging, and the loading state when switching tasks.
- Chrome The old and new templates cover 320/360/390/640/768/1328/1920px, mobile landscape, 20 rows of long emails/long errors, pagination button edges, scroll/focus retention on refresh, reset on paging, nested Escape, empty state, and HTML escaping; all passed.
- compileall, `git diff --check` passed. This round used a mock API and desktop Chrome to simulate different viewports; no real account network requests were run, and real-device Safari was not covered.

## Deactivated-skip and one-click delete (2026-10-18)

- After claiming an account, inspection first checks `live_check_status=deactivated` and skips AT parsing, liveness check, and plan query directly. It counts toward `skipped_count` like accounts deleted before execution, and is also counted separately in `deactivated_skipped_count`; `checked_count`, `invalid_count`, and the actual liveness check failure count do not increase.
- Deactivated skips are written to the failure details with type `deactivated_skipped`, storing the email and reason at the time, committed in the same transaction as the skip stats. The details button count is actual liveness check failures plus deactivated skips, and the history progress shows the total skipped and how many of them are deactivated; missing fields on legacy tasks are shown as 0.
- The account management area of the old and new account lists gains a Delete All Deactivated button. After confirming the current archive scope, it deletes all deactivated accounts in that scope, not limited to the current page and unaffected by search and other filters. The unarchived and archived scopes do not affect each other; the email pool and inspection history are not deleted.
- API: `POST /api/accounts/delete-deactivated`, JSON `{ "archived": "0" | "only" | "all" }`. A valid scope must be given explicitly, login authentication is reused; returns `deleted_count`.
- Deletion matches against the latest state inside a single SQLite write transaction and also cleans up the associated Agent credentials; the account collection is not fully loaded/rewritten in Python, and normal account payloads stay unchanged. On deletion failure, accounts and credentials roll back together.
- New regressions cover: deactivated accounts with valid/expired ATs make no liveness check request, skip and detail stats, history retained after deletion, archive scope isolation, protection of accounts that have recovered to normal, Agent credential cleanup, deletion rollback, API authentication and parameter validation, and frontend confirmation / duplicate-submit guard / failure recovery.
- Verification: 393 tests pass in the full run (final re-run 20.358 s), 76 inspection-specific tests pass (5.986 s), and the Node UI and Chrome mock-API layout regressions pass; no real account network requests were run.

- This round toolbar test isolates the fixed sidebar shell and verifies that the tool group holding the new delete button wraps in a narrow container; it does not mean full-site mobile sidebar adaptation is complete.

## Focused review of the deactivated feature (2026-10-18)

- Reproduced and fixed a concurrent refresh defect in the old and new account lists: while an old list request was unfinished, the post-delete refresh was dropped outright. Now follow-up refreshes are merged, stale old responses are discarded, and the latest list is re-read after the current request ends.
- Also fixed the re-read lock being released too early after the page count shrinks, so list requests stay serialized; the account list gets a 30-second cancel timeout, and on failure/timeout the lock is released and pending refresh requests are handled.
- Reproduced and fixed the shared `api()` swallowing response-body cancellation: if reading the JSON times out after the headers arrive, the AbortError must not be converted into a successful empty object; previously this could wrongly clear the list or report the delete result as a successful 0.
- Added `node tests/test_account_list_reload_ui.cjs`, which extracts the real functions directly from the old and new templates and covers refresh merging, no echo of old lists, the shrink-page lock, failure/timeout recovery, and response-body cancellation.
- The backend adds validation of contention with an external SQLite write transaction: after waiting for other writers it re-matches against the latest committed state and does not delete accounts that have recovered to normal; when writing the details of a deactivated skip fails, the total skip count and the deactivated skip count roll back together.
- This round the full run passed 395 tests (final re-run 27.161 s) and the inspection-specific run passed 78 tests (7.106 s); the two Node UI regression groups, the Chrome mock layout regression, compileall, and the diff check passed.
- Performance sample: temporary SQLite, account payload about 4KB, 20% marked deactivated, no Agent credentials; deleting 2000 of 10k rows took about 0.508 s, deleting 10k of 50k took about 2.853 s; an empty delete on the 50k sample afterwards took about 0.294 s. These are samples from the current machine only, not a timing commitment.
- Deletion does not fully deserialize/rewrite accounts, and Python allocates no complete account list; the status is still inside the payload, so filter cost grows linearly with account count and payload size. A large batch deletion holds the SQLite write lock (WAL allows parallel reads); the transaction was not split to reduce lock time, preserving the atomicity of deleting accounts and Agent credentials.
