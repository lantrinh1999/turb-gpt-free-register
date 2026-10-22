

## Latest review (2026-10-18)

This round re-reviewed task claiming/de-duplication, account snapshots and stale-result protection, exception reclamation, history recovery, database locks, and UI request state; **no new functional defects or blocking performance issues were confirmed, and no business code was modified this round**. This is a conclusion for a fixed review scope, not a guarantee that the whole system is defect-free.

- Full unittest run: 384 tests passed (20.003 s).
- Inspection-specific: 67 tests passed in 3 consecutive rounds (6.834 / 6.989 / 6.642 s), including mixed concurrency with 1/4/16/32 threads, de-duplication, and exact statistics verification.
- Node UI Regression, system Chrome desktop/mobile rendering of the old and new templates, compileall, `git diff --check`: passed.
- Local temporary DB benchmark: 1000 primary-key reads took 2.181 s, 100 accounts with 6 status operations each took 1.791 s, and an 8-thread inspection of 1000 valid ATs took 3.016 s. This round ran in parallel with the regression suite, so single timings are for observation only and not for strict performance attribution.
- Logs: `/tmp/inspection-reaudit-full.log`, `/tmp/inspection-reaudit-{1,2,3}.log`; benchmark: `/tmp/inspection-reaudit-perf.json`.
- Remaining design boundaries: loading all IDs at once costs O(N) memory; Unicode email matching may scan the email column; SQLite single-writer and synchronous stats still cap throughput; network requests use mocks, so real login / code retrieval / plan latency was not measured this round. The existing cross-process account-editing boundary is unchanged.

The existing acceptance matrix and the evidence from each fix are kept below.
## Follow-up storage optimization regression

Reads by account primary key and single-row transactional updates for liveness check/plan are now in place; the original acceptance invariants are unchanged, and statistics are still persisted stage by stage. After the optimization the full test run has **373 tests passing**, with **56** inspection-specific tests; performance samples, change scope, and new regressions are in `docs/account-inspection-performance.md`. Other features still do full-collection read-modify-write, and the original multi-instance deployment boundary still applies.

## ID list and abnormal-stop review results

The latest regression: **378 tests pass in the full run, and the 61 inspection-specific tests pass in 3 consecutive rounds**. Added verification for separating the list from statistics, legacy record migration and failure rollback, and stopping further claims after a thread fault; detailed evidence and the remaining performance boundaries are in the appended section of `docs/account-inspection-performance.md`. IDs are still loaded all at once, and the validation boundaries for network mocks and multi-instance account editing are unchanged.

## Email entry compatibility and performance review

Latest verification: **381 tests pass in the full run, and the 64 inspection-specific tests pass in 3 consecutive rounds**. Fixed lookups by email still loading all account details, and the mismatch between single-row SQL queries and Python Unicode lowercase semantics. Reproductions and performance samples are in the appended section of the performance report. The rest of the acceptance scope and the declared boundaries are unchanged.

## 2026-10-18 lock contention and resource reclamation review

The latest full run has **384 passing tests**, with **67** inspection-specific tests. Fixed three paths: idle history recovery checks unconditionally taking the write lock, a connection not closed when connection configuration fails, and a connection not closed when database initialization fails early. Evidence from a real SQLite write lock and resource fault injection is in that day section of the performance report; other validation boundaries are unchanged.
