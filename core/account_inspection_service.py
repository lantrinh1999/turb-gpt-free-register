# -*- coding: utf-8 -*-
"""Local AT expiry inspection; the liveness check (which also checks the plan in the same session) is only called for invalid accounts."""
from __future__ import annotations

import logging
import math
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from contextlib import contextmanager

from core.inspection_lease import acquire_inspection_lease

from core import db, live_check_service
from core.chatgpt_plan import decode_jwt_payload_unverified, normalize_token

logger = logging.getLogger(__name__)
DEFAULT_WORKERS = 3
MAX_WORKERS = 32
_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="account-inspection")


def token_needs_refresh(token: str, now: float | None = None) -> bool:
    """Only the JWT exp is read, the API is not accessed; missing/malformed ones are also treated as invalid."""
    if not isinstance(token, str):
        return True
    token = normalize_token(token)
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return True
    payload = decode_jwt_payload_unverified(token)
    exp = payload.get("exp") if isinstance(payload, dict) else None
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return True
    try:
        return not math.isfinite(exp) or exp <= (time.time() if now is None else now)
    except (ValueError, OverflowError):
        return True


def _check_live(account: dict, executor: ThreadPoolExecutor) -> dict:
    queued = live_check_service.enqueue_account_live_check(
        account_id=account["id"], email=account.get("email", ""),
        trigger="inspection", return_future=True, executor=executor,
    )
    if not queued.get("accepted"):
        return {"ok": False, "status": "rejected", "error": queued.get("error") or "Liveness check enqueue was rejected"}
    return queued["future"].result()


def validate_workers(workers: int) -> int:
    if type(workers) is not int or not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"The number of inspection threads must be an integer from 1 to {MAX_WORKERS}")
    return workers


class InspectionStopped(RuntimeError):
    """The persisted task has finished; the old worker no longer runs later stages."""


def _run(run: dict) -> None:
    # Each ID enters the shared iterator only once; claiming and statistics are locked separately.
    account_ids = list(dict.fromkeys(run["account_ids"]))
    run["account_ids"] = account_ids
    run["total_count"] = len(account_ids)
    run.setdefault("skipped_count", 0)
    run.setdefault("deactivated_skipped_count", 0)
    pending = iter(account_ids)
    claim_lock = threading.Lock()
    stats_lock = threading.Lock()
    stopped = threading.Event()

    def persist(failure=None):
        saved = db.save_account_inspection(run, failure=failure) if failure is not None else db.save_account_inspection(run)
        if not saved:
            raise InspectionStopped("The inspection task has finished or was interrupted")

    def record(*, failure=None, **counts):
        with stats_lock:
            previous = {key: run[key] for key in counts}
            for key, value in counts.items():
                run[key] += value
            try:
                persist(failure)
            except BaseException:
                # When writing the detail row to the database fails, the finally block must not save the failure count that has already been incremented on its own.
                run.update(previous)
                raise

    def inspect_account(account_id, stage_executor):
        account = db.get_account(account_id)
        if account is None:
            record(skipped_count=1)
            return
        if str(account.get("live_check_status") or "").strip().lower() == "deactivated":
            record(skipped_count=1, deactivated_skipped_count=1, failure=dict(
                account_id=account_id, email=account.get("email", ""), status="deactivated_skipped",
                error="The account is already marked as dead, this inspection skips it and does not run the AT check, liveness check or plan check." +
                      (" Reason:" + str(account["live_check_error"]) if account.get("live_check_error") else ""),
            ))
            return
        invalid = token_needs_refresh(account.get("access_token", ""))
        record(checked_count=1, invalid_count=int(invalid))
        if not invalid:
            return
        try:
            live_result = _check_live(account, stage_executor)
        except Exception as exc:
            logger.exception("Inspection liveness check error account_id=%s", account_id)
            live_result = {"ok": False, "status": "error", "error": f"{type(exc).__name__}: {str(exc)[:1500]}"}
        live_ok = bool(live_result.get("ok"))
        counts = {"live_success_count" if live_ok else "live_failed_count": 1}
        if live_ok:
            plan_ok = bool((live_result.get("plan_result") or {}).get("ok"))
            counts["plan_success_count" if plan_ok else "plan_failed_count"] = 1
        failure = None if live_ok else dict(account_id=account_id, email=account.get("email", ""),
                                            status=live_result.get("status") or "failed",
                                            error=live_result.get("error") or "Liveness check failed, no specific reason returned")
        record(failure=failure, **counts)

    def worker(stage_executor):
        while True:
            with claim_lock:
                if stopped.is_set():
                    return
                account_id = next(pending, None)
            if account_id is None:
                return
            try:
                inspect_account(account_id, stage_executor)
            except BaseException:
                # After one worker hits a storage/execution fault, other workers should not keep claiming the whole list.
                # Accounts already being processed still finish up, to avoid leaving behind sessions and queue occupation.
                stopped.set()
                raise

    try:
        workers = validate_workers(run.get("workers", DEFAULT_WORKERS))
        run["status"] = "running"
        persist()
        # Independent stage thread pool, not limited by the fixed thread count of the manual liveness check; it still reuses the unified account occupation and rate limiting.
        # Stage execution and the inspection workers waiting for it use separate pools, to avoid thread-pool starvation deadlock.
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="inspection-stage") as stages:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="inspection-worker") as pool:
                futures = [pool.submit(worker, stages) for _ in range(min(workers, len(account_ids)))]
                for future in futures:
                    future.result()
        run["status"] = "completed"
    except InspectionStopped as exc:
        run.update(status="interrupted", error=str(exc))
    except Exception as exc:
        logger.exception("Account inspection error")
        run.update(status="failed", error=f"{type(exc).__name__}: {str(exc)[:200]}")
    finally:
        run["finished_at"] = datetime.now().isoformat(timespec="seconds")
        db.save_account_inspection(run)


@contextmanager
def startup_recovery_guard():
    """While an inspection on the same database still holds the process lock, other instances must not restore it and its stage tasks to failed."""
    lease = acquire_inspection_lease()
    try:
        yield lease is not None
    finally:
        if lease is not None:
            lease.close()


def _run_with_lease(run, lease):
    try:
        _run(run)
    finally:
        lease.close()


def _release_cancelled_inspection(future, run, lease):
    if not future.cancelled():
        return
    try:
        cancelled = dict(run, status="interrupted", finished_at=datetime.now().isoformat(timespec="seconds"),
                         error="The inspection was cancelled before it started executing")
        db.save_account_inspection(cancelled)
    except Exception:
        logger.exception("Failed to write the inspection cancelled state")
    finally:
        lease.close()


def _recover_orphaned_inspections() -> None:
    # The caller must hold the process lock; there is then no running inspection, so state left by an abnormal exit can be cleaned up.
    db.recover_interrupted_account_inspections(
        error="The inspection executor has exited or the task was interrupted abnormally; the task occupation has been released and the statistics keep the completed part")


def list_inspections(limit: int = 50, offset: int = 0) -> dict:
    # Does not depend on a restart: if the last database write failed, the next poll can also clear the false busy state.
    lease = acquire_inspection_lease()
    try:
        if lease is not None:
            _recover_orphaned_inspections()
        return db.list_account_inspections(limit=limit, offset=offset)
    finally:
        if lease is not None:
            lease.close()


def start_inspection(workers: int = DEFAULT_WORKERS, archived: str | bool = "0") -> tuple[dict, bool]:
    workers = validate_workers(workers)
    if type(archived) is bool:
        archived = "only" if archived else "0"
    if not isinstance(archived, str) or archived not in ("0", "only", "all"):
        raise ValueError("The archive scope must be 0 (not archived), only (archived) or all (everything)")
    lease = acquire_inspection_lease()
    if lease is None:
        active = db.list_account_inspections()["active"]
        return active or {"status": "queued", "error": "The inspection is starting or finishing up, please retry later"}, False
    submitted = False
    try:
        _recover_orphaned_inspections()
        run, created = db.create_account_inspection(workers=workers, archived=archived)
        if created:
            try:
                future = _EXECUTOR.submit(_run_with_lease, run.copy(), lease)
                submitted = True
                future.add_done_callback(lambda done: _release_cancelled_inspection(done, run, lease))
            except Exception as exc:
                run.update(status="failed", error=str(exc)[:200], finished_at=datetime.now().isoformat(timespec="seconds"))
                db.save_account_inspection(run)
                raise
        return {k: v for k, v in run.items() if k != "account_ids"}, created
    finally:
        if not submitted:
            lease.close()
