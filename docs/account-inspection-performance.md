# Inspection storage performance optimization (2026-10-17)

## Implemented

- `get_account()` Target accounts are read by SQLite primary key, no longer loading and deserializing all accounts.
- The 6 hot paths of liveness check/plan (claim, in-progress marking, result saving) now do incremental updates on the target row; the whole account table is no longer deleted and re-inserted.
- `BEGIN IMMEDIATE` The transaction covers target row read, ownership/snapshot validation, and write-back; write exceptions roll back. No UPDATE is executed when nothing changed.
- Keeps SQL columns consistent with the JSON payload and `copy_line`; keeps the legacy matching order when the old API passes both ID and email.

## Unchanged this round

- Inspection thread count, account de-duplication, archive snapshot, automatic plan query in the same session, shared plan rate limiting.
- Stage-by-stage statistics persistence, terminal-state protection, and marking interrupted on restart; speed is not bought with buffered statistics.
- No account snapshot cache was introduced; account deletion, email change, and AT updates are still validated against the current database state.
- Full-collection writes in other features were not refactored; this round transaction rework must not be equated with whole-project support for editing accounts from multiple instances at once.

## Local before/after comparison

Same macOS machine, same Python environment, temporary SQLite, 1000 accounts, all ATs valid; no external network. One sample each before and after the change, times in seconds, affected by machine load, and not representative of the speedup on the real login path.

| Workload | Before | After | Approx. speedup |
|---|---:|---:|---:|
| Read 1000 accounts one by one | 9.002 | 1.442 | 6.2x |
| 100 accounts, 6 liveness check/plan status operations each | 20.411 | 1.572 | 13.0x |
| 8 threads inspecting 1000 valid ATs (including stage-by-stage stats persistence) | 12.178 | 3.186 | 3.8x |

Repeatable (temporary database only):

```sh
.venv/bin/python tests/benchmark_account_inspection.py
```

Returns seconds for three items: `read_1000`, `lifecycle_100`, and `valid_inspection_1000`. Real invalid accounts still have to wait for login, email verification codes, plan requests, and rate limiting, so the multiples above cannot be used to estimate the duration of a whole round.

## Regression and re-review

- Full unittest run: 373 tests passed.
- Added 4 regressions: hot paths forbid full read/write, with triggers protecting other accounts; transaction exception rollback, index column and payload consistency, and a missing account not being resurrected; actual SQL write failure rollback; email matching compatibility.
- 56 inspection-specific tests, passed in 3 consecutive rounds (5.358 / 4.758 / 5.185 s): covering 1/4/16/32 threads, legacy task ownership, cancellation, email change, AT change, network/storage/cleanup faults, and exact statistics.
- Node UI Regression, compileall, and `git diff --check` passed; the UI was not modified this round.
- Re-review confirmed: the transaction closes before the public method returns, and a commit failure raises instead of returning a false success; a snapshot mismatch that returns False early still persists the necessary failure status; no network request is executed while holding a database transaction.

## Appendix: ID list and abnormal-stop focused check

### Confirmed and fixed

1. **Stats updates repeatedly carried the full ID list.** Previously every account stats write-back serialized the entire `account_ids`, so the list processing of a round grew roughly quadratically with the number of accounts; although the history API does not return IDs, it still read and parsed these lists. The immutable list is now stored separately in `account_inspection_snapshots`, and the task summary stores only the status and counts. The list and the new task are created in the same transaction; existing records are migrated once at startup, and a failed migration rolls back and closes the connection, after which it can be retried. Stats are still persisted stage by stage, and the stats buffering window was not widened.
2. **Other threads kept claiming after a thread fault.** When one inspection worker exited because of a database read/stats save fault, the other workers could previously continue processing the remaining list. A shared stop event now stops further claims; accounts already claimed may finish their current processing and resource cleanup, and the task record is marked failed or interrupted.
3. Inspection table and index creation was moved into database initialization, so DDL is no longer repeated on every stats save or history read.

### Large-list validation (local temporary SQLite, no network)

| Accounts in list | 100 consecutive stats writes | Characters in a single stats JSON |
|---|---:|---:|
| 1000 | 0.248 s | 313 |
| 10000 | 0.242 s | 314 |
| 100000 | 0.240 s | 315 |

This validation checks that the stats write cost does not grow with the ID list size; it is not the same as running 100k real liveness checks. The ID list itself is still loaded all at once at startup, taking O(N) space, and historical snapshots still occupy disk; no claim of unlimited scale is made and no on-disk paged scheduling was introduced.

### Final verification

- Full unittest run: **378 tests passed** (16.810 s).
- Inspection-specific: **61 tests, passed in 3 consecutive rounds** (5.204 / 5.257 / 5.646 s), keeping the mixed-concurrency regression with 1/4/16/32 threads.
- Added: size constraint on stats for lists of tens of thousands of IDs and snapshot immutability, legacy record upgrade and restart recovery, migration failure rollback and lock release, task creation rollback when saving the list fails, and a two-worker fault test for stopping claims.
- Node UI, compileall, and `git diff --check` passed.
- The second re-review confirmed that the list is written only at creation / legacy record migration, and ordinary history reads and task status saves do not read the list table; the unique active index, terminal-state write protection, archive snapshot, and the external API fields are unchanged.

### Remaining performance boundaries

- Loading all IDs at once and defensive de-duplication cost O(N) memory, which suits the current list scheduling model; very large scale would need persistent paged claiming.
- Stats use synchronous persistence and SQLite writes remain serialized; this is the current trade-off to preserve fault-recovery stats.
- Login, code retrieval, and shared plan rate limiting still determine the total time for invalid accounts, so the actual network path speed cannot be estimated from a local scan benchmark.

## Appendix: email entry re-check after the single-row rework

Fixed scope: single-row read / transactional write-back, Unicode email compatibility, the log polling entry, list migration, and the concurrent stop path.

### Confirmed issues and fixes

- `get_account_by_email()` still uses collection reads; the pre-login account lookup and the liveness log polling load all payloads. They now filter in SQLite and decode and return only the one matching payload, so Python no longer loads all account details.
- The previous round `_select_account()` used SQLite `LOWER(email)`, which only handles ASCII and is incompatible with the historical Python `str.lower()`. For example `Élodie` or the Kelvin sign `K` could fail to match or pick the wrong first account. The connection now registers a dedicated query function `account_email_lower()`, restoring the original matching semantics; the built-in SQLite function is not overridden and existing index definitions are not changed. The primary-key hot path is unaffected by this function.
- Keeps the legacy behavior: duplicate emails match the first row by ID, empty emails are handled as before, and input spaces are not stripped automatically.

Both issues were first reproduced by regression tests and then fixed. Added 3 regressions covering the ban on collection reads, mixed Unicode/ASCII email matching, and duplicate/empty email compatibility.

### Performance and scope

Local temporary SQLite, 1000 accounts each with a 2000-character note, 100 consecutive lookups of the last account: the old collection path took 2.223 s, the new path 0.476 s, about 4.7x; no network. To preserve Unicode semantics, email matching may still scan the email column (O(N)), so not everything became an indexed query; the main gain is no longer loading and deserializing all account payloads. Primary-key reads remain indexed queries.

This round did not change scheduling, rate limiting, stats persistence, list migration, or the process lock. The second review pass found no new blocking defects in those existing paths; the existing boundaries of one-time ID memory cost, synchronous stats writes, collection writes in other features, and real-network mocking still apply.

Final verification this round: full run **381 tests passed** (34.113 s); inspection-specific **64 tests passed in 3 consecutive rounds** (6.736 / 11.252 / 7.967 s); Node UI, compileall, and `git diff --check` passed. Logs: `/tmp/inspection-email-repro.log` (pre-fix reproduction), `/tmp/inspection-audit-full-final.log`, `/tmp/inspection-audit-repeat-{1,2,3}.log`.

## 2026-10-18: lock contention and initialization resource re-check

Scope of this round: concurrent de-duplication, thread-fault reclamation, single-row account writes, snapshot migration, UI request state, and database behavior under frequent history polling.

### Pre-fix reproduction and fix

1. **Idle history queries contended for the write lock.** `recover_interrupted_account_inspections()` executed `BEGIN IMMEDIATE` whether or not any unfinished task existed. While another connection held an unrelated write transaction, idle history polling waited or even reported `database is locked`. Added a regression where a real SQLite connection holds the write lock and the busy timeout of the connection under test is set to 50ms; it failed consistently before the fix. The fix first does a read-only check and returns directly when there is no task to recover; when tasks exist it takes the write lock and re-reads, so the recovery write-back uses the state read under the lock.
2. **A failed connection configuration did not close the connection.** When function registration or PRAGMA setup in `_sqlite_conn()` raised, the caller had not yet received the connection and could not clean it up. The exception path now closes the connection explicitly and preserves the original exception.
3. **An early failure in database initialization did not close the connection.** Previously only the tail of the snapshot migration was protected by cleanup, so exceptions in table/index creation and other initialization stages could still rely on garbage collection. The initialization body is now wrapped by both connection closing and a transaction context; on a fault, uncommitted operations are rolled back and the connection closed, and READY is set only after the context exits successfully. There is no promise that DDL and previously committed legacy data imports can be rolled back as a whole.

3 new regressions each failed first and were then fixed; the logs are `/tmp/inspection-resource-repro.log` and `/tmp/inspection-resource-fixed.log`.

### Re-review conclusions and verification

- Full unittest run: **384 tests passed** (17.584 s).
- Inspection-specific: **67 tests**, including idle history reads under a real write lock, closing on connection configuration failure, and closing on index creation failure; kept snapshot migration rollback, legacy task overwrite protection, exact concurrent stats, and the 1/4/16/32-thread tests.
- Node UI, compileall, `git diff --check` passed.
- Re-checked the exit order of the initialization context: transaction commit/rollback precedes close, and READY is set after a successful exit; active task recovery still re-checks under the write lock and does not use the stale payload from the read check.
- Scheduling mode, concurrency limit, rate limiting, and stage-by-stage stats persistence were not changed; the existing boundaries of O(N) ID memory cost, Unicode email column scan, SQLite single writer, and network mocking are unchanged. No other blocking issues with clear evidence left unhandled were found within the fixed scope above.

Final 3 consecutive rounds of the inspection-specific tests passed: 67 tests, 5.037 / 5.602 / 5.388 s. Full log: `/tmp/inspection-resource-full.log`; specific logs: `/tmp/inspection-resource-repeat-{1,2,3}.log`.
