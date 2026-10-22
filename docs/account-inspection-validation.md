# Account inspection acceptance record

Date:2026-10-17

## Acceptance scope and conventions

- The account ID set and the archive scope are fixed at start: unarchived / archived / all. Other list filters do not take part in inspection; the dialog says so explicitly.
- Each account is claimed at most once within a task, with 1-32 concurrent pipelines supported; stage requests reuse the existing queues and rate limiting.
- Only one inspection is allowed per SQLite database; the database unique constraint and the process file lock together prevent duplicates.
- AT is checked locally only: the JWT exp is read without any API request and without signature verification; missing, malformed, or expired tokens are all treated as invalid.
- Only invalid accounts get a liveness check. The liveness check first saves the new AT, then reuses the same BrowserSession to query the plan; inspection only consumes the `plan_result` returned by the liveness check and no longer submits a separate plan query. A rejected occupation also counts as a failure of the corresponding stage.
- Deleted before the check starts: counted as skipped. Deleted / email changed / AT changed during the request: the old result is rejected and counted as a stage failure, not a success.
- Tasks after a restart are marked interrupted, keeping the persisted stats; they do not resume automatically and login requests are not replayed. Users can start a new task.
- While the active instance still holds the process lock, other instances initializing will not interrupt that inspection by mistake. If the final status write fails, a later history query can clean up the leftover occupation that has no executor.
- completed means all accounts were processed, not that all liveness checks / plans succeeded. For interrupted or failed tasks, the stage counts may be lower than the number of invalid accounts, indicating stages not yet completed.

## Automated regression matrix

| Category | What is verified | Test location |
|---|---|---|
| JWT | time boundary, invalid exp, non-string, empty or multiple segments,Bearer | `test_account_inspection.py` |
| Flow and counts | A normal token does not call the service; after the liveness check the new AT is read; success / failure / rejection counts | Same as above |
| Concurrency and de-duplication | Multi-account concurrency, thread count validation, single claim per ID, global mutual exclusion | Same as above |
| Archive | Three-scope snapshots, history identifier, archive state retention | Same as above and UI tests |
| Dynamic accounts | Skip on deletion, IDs not reused, no false success during deletion, old results rejected after email change and AT update | Same as above |
| Restart and recovery | queued/running interrupted, old workers do not revive terminal states, repeated initialization does not kill by mistake | Same as above |
| Process mutual exclusion | Real child processes contending for the lock, lock released automatically on process exit | Same as above |
| Resource release | claim/submit/log failure, Future cancellation, proxy close failure | Same as above |
| Persistence | History pagination, terminal-state protection, polling recovery after a failed final save | Same as above |
| HTTP/UI | authentication, invalid JSON, parameter bounds, old and new templates, stale-response isolation, GET timeout recovery, refresh after completion | Same as above and `test_account_inspection_ui.cjs` |

## New fixes this round

1. Liveness check / plan write-back now carries conditions on the account email and AT snapshot, compared under the database lock, so an email change or refresh during a network request is not overwritten by an old result.
2. Liveness check / plan results that failed to persist are no longer treated as inspection successes and do not enter the later success path.
3. The inspection history GET gains a 30-second cancel mechanism, so a hung network cannot occupy the frontend loading state forever.

## Conclusions on the two originally failing tests

- authorize implementation explicitly allows a limited number of 403 retries within the same session and keeps the cookies; the original test required an immediate first failure, which contradicts the current policy. The business policy was not changed; added behavior checks for same-session retry success, retry exhaustion/backoff, and immediate failure on 400.
- 2FA uses a fixed-maximum-capacity thread pool plus a dynamically configurable logical concurrency gate, while the original test treated the two as one value. Added a real worker test that verifies the concurrency limit, dynamic increase/decrease, and resource return after a task exits; the concurrency policy was not changed.

## Verification commands

```sh
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m unittest discover -s tests -p 'test_account_inspection.py' -q
node tests/test_account_inspection_ui.cjs
.venv/bin/python -m compileall -q core webui tests
git diff --check
```

## Verification boundaries

- External login, email, and plan requests use mocks; no bulk network calls were made against real accounts.
- Frontend async tests run in a Node VM; Chrome was also used for desktop/mobile layout checks of the old and new templates (mock data), which is not equivalent to real server end-to-end acceptance.
- The file-lock child-process tests ran on the current macOS environment; they were not validated on Windows or network file systems.
- Automatic resume after restart is not supported. Stage results not yet persisted when a process crashes cannot be recovered, and no cross-crash exactly-once guarantee is claimed for external requests.
- The scope of this round is account inspection and its direct dependency chain; it does not mean all other project features have been fully audited.

## Actual results this round

- Full unittest run: all 347 tests passed, 0 failures.
- Inspection-specific: all 39 tests passed, and all 3 repeated consecutive rounds passed.
- Node frontend async regression: passed.
- Python compileall: passed.
- git diff --check: passed.

Full log: `/tmp/inspection-final-validation.log` (a local temporary file, not saved with the repo).


## Inspection dialog UI polish acceptance

- Uses the existing `--surface` / `--line` color variables of the page, fixing the conflict of dark text on a dark background.
- The start and history dialogs share the same title, buttons, and margins; long rules are shown collapsed.
- Statistics use grouped success/failure numbers, status tags, and a progress bar, keeping the skipped count and the full task times.
- Added loading, empty-record, and first-read-failure states; the refresh button shows an in-progress state.
- Chrome Verified with mock data on both the old and new templates, covering 1328px desktop, 390px mobile, dialog bounds, Escape to close, empty state, and HTML escaping.
- Node Async UI tests passed; the full unittest run of 347 tests passed.


## Automatic plan query in the same session after a liveness check

### Current flow

1. Manual / batch / inspection / post-email-change liveness check completes the login and obtains a new AT.
2. First validate against the account snapshot and save the AT, so the login result is not lost if the plan request fails or waits.
3. Query the plan with the same BrowserSession, cookies, fingerprint, and proxy that are not yet closed; no extra session or proxy relay is created.
4. The automatic plan query shares account occupation, queue capacity, and request rate limiting with the manual plan queue; it runs synchronously inside the current liveness check thread instead of submitting to the same stage thread pool and waiting.
5. After the plan result is saved, the original liveness check flow closes the session and the proxy relay uniformly. A plan error does not trigger re-login and does not turn the liveness check into a failure.
6. Inspection only calls the liveness check and accumulates the liveness check and embedded plan results separately. Accounts whose AT has not expired are still checked only via the local JWT, with no business API called.

### Concurrent overwrite protection

- Plan writes validate the email, the AT, and the run ID of this query; an old request must not finish or overwrite a later query.
- If the account email / AT changes while this query is executing, the old result is discarded and its own occupation state is ended, leaving no false running state.
- After the liveness check result has been saved early, the old AT is not written again when the plan finishes.
- The run identifier in the liveness check log covers the automatic plan stage, so the frontend does not stop polling early.

### This verification

- Full unittest run: all 356 tests passed.
- Inspection-specific: 44 tests; verified original session propagation, early writing of the new AT, plan failure isolation, shared de-duplication, discarding results of old runs, and complete concurrent tasks without deadlock.
- Plan low-level tests: a borrowed session is not closed by the callee after success / 401 / 503 / 403 retries, and the session or proxy is not rebuilt and warm-up is not repeated.
- The liveness check after an email change that queries the plan in the same session has regression coverage.
- Node UI Regression, compileall, and git diff --check passed.
- All external account network operations use mocks; no real account login or plan request was executed.

## Exception path audit after the same-session rework

This round first reproduced the failures by fault injection, then changed the implementation, confirming the following 3 fixes:

| Problem | Fix | Regression test |
|---|---|---|
| After the auth callback that saves the AT raised, the completion flag was set early, so a later exit retry failed and skipped the final status write, leaving the account stuck in running | The completion flag is set only after the callback returns normally, and the flag is reset on each exit attempt | `test_auth_callback_save_failure_then_retry_does_not_leave_live_running` |
| The plan task failed to write the database at startup before the run ID was written, so the ownership check in the exception handler did not match and the task stayed queued | The run ID is persisted at claim time and carried through start, completion, submit failure, and cancellation; a failure write may end its own queued state, and an old task must not start or end a new task | `test_plan_start_database_error_releases_persisted_queue_claim`,`test_old_plan_run_cannot_finish_newer_claim` |
| After a standalone plan query succeeded, a proxy relay close error overwrote the original success result | Relay closing is best-effort: the cleanup exception is logged but the business result is kept | `test_relay_close_failure_does_not_discard_successful_standalone_plan` |

Final full test run: all 359 tests passed. Inspection-specific: all 46 tests passed. Node UI regression, compileall, and git diff --check passed. External network uses mocks and no real account was called.

## Second round of interleaving and resource lifecycle review

- Ownership of the session in a full web login belongs to the login function until it returns. When authorization failed, a dead account was detected, or an OTP raised, the original code neither handed the new session to the caller nor closed it itself, leaking the resource. It is now closed uniformly on the exception path and handed to the liveness check caller only on the success path; a close failure does not override the original login exception.
- When the liveness check finally cleaned up the log file, a `FileHandler.close()` exception used to override the business success return. The log handler is now removed first and then closed best-effort, keeping the liveness check / plan result and releasing the run marker.
- Added 4 test methods covering close on failure in the authorization / dead-account / OTP stages, keeping the session open on success, a cleanup exception preserving the original error, and a log close exception preserving the success result.
- Full unittest run: all 363 tests passed. Inspection-specific: 46 tests passed. Node UI, compileall, and diff checks passed. External network still uses mocks.
