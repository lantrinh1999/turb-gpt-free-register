# -*- coding: utf-8 -*-
"""Plan/Plus eligibility query background queue."""
from __future__ import annotations

import logging
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from config import proxy as proxy_cfg
from core import db
from core.chatgpt_plan import check_account_plan

logger = logging.getLogger(__name__)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(proxy_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(getattr(proxy_cfg, name, default) or 0.0)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("PLAN_CHECK_WORKERS", 3, 1, 16)
_QUEUE_LIMIT = _int_setting("PLAN_CHECK_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="plan-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_LOCK = threading.Lock()
_RUNNING: set[int] = set()
_RATE_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0


def _wait_for_rate_slot() -> None:
    """Assign staggered request start times to all query threads."""
    global _NEXT_REQUEST_AT
    min_interval = _float_setting("PLAN_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0)
    jitter = _float_setting("PLAN_CHECK_JITTER", 0.3, 0.0, 30.0)
    with _RATE_LOCK:
        now = time.monotonic()
        scheduled = max(now, _NEXT_REQUEST_AT) + (random.uniform(0.0, jitter) if jitter else 0.0)
        _NEXT_REQUEST_AT = scheduled + min_interval
    wait_seconds = scheduled - now
    if wait_seconds > 0:
        time.sleep(wait_seconds)


def _registration_recheck_delay() -> float:
    return _float_setting("PLAN_CHECK_REGISTRATION_RECHECK_DELAY", 2.0, 0.0, 30.0)


def _run_plan_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None,
    timezone_offset_min: str,
    session=None,
    run_id: str | None = None,
) -> dict:
    expected_account = {"email": email, "access_token": access_token}
    run_id = run_id or uuid.uuid4().hex
    try:
        _wait_for_rate_slot()
        if not db.mark_account_plan_check_running(account_id, run_id=run_id, expected_account=expected_account):
            return {"ok": False, "error": "Account deleted, email/AT changed, or plan task was reset"}
        session_options = {"session": session} if session is not None else {}
        result = check_account_plan(
            access_token,
            proxy=proxy,
            timezone_offset_min=timezone_offset_min,
            **session_options,
        )

        recheck_delay = _registration_recheck_delay()
        should_recheck = (
            trigger == "registration_auto"
            and recheck_delay > 0
            and bool(result.get("ok"))
            and str(result.get("current_plan_type") or "").lower() == "free"
            and not bool(result.get("plus_trial_eligible"))
        )
        if should_recheck:
            logger.info("[Plan] No Plus trial eligibility found for the new account yet, rechecking once in %.1fs: %s", recheck_delay, email)
            time.sleep(recheck_delay)
            _wait_for_rate_slot()
            if not db.mark_account_plan_check_running(account_id, run_id=run_id, expected_account=expected_account):
                return {"ok": False, "error": "Account changed, canceling plan recheck"}
            recheck_result = check_account_plan(
                access_token,
                proxy=proxy,
                timezone_offset_min=timezone_offset_min,
                max_attempts=1,
                **session_options,
            )
            if recheck_result.get("ok"):
                result = recheck_result
            else:
                logger.warning(
                    "[Plan] New account eligibility recheck failed, keeping the first successful result: %s, %s",
                    email,
                    recheck_result.get("error") or "Unknown error",
                )

        if not db.update_account_plan_check(acc_id=account_id, result=result, expected_account=expected_account, expected_run_id=run_id):
            return {"ok": False, "error": "Account deleted or email/AT changed, discarding the old plan result"}
        if result.get("ok"):
            logger.info(
                "[Plan] Background query succeeded: %s, plan=%s, plus_trial=%s, trigger=%s",
                email,
                result.get("current_plan_type") or "unknown",
                bool(result.get("plus_trial_eligible")),
                trigger,
            )
        else:
            logger.warning(
                "[Plan] Background query failed: %s, trigger=%s, error=%s",
                email,
                trigger,
                result.get("error") or "Unknown error",
            )
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
        }
        try:
            db.update_account_plan_check(acc_id=account_id, result=result, expected_account=expected_account, expected_run_id=run_id)
        except Exception:
            logger.exception("[Plan] Failed to write background query error status: account_id=%s", account_id)
        logger.exception("[Plan] Background query error: %s", email)
        return result
    finally:
        with _LOCK:
            _RUNNING.discard(int(account_id))
        _QUEUE_SLOTS.release()


def _release_cancelled_check(future, account_id: int, run_id: str | None = None) -> None:
    # A canceled Future that has not run never enters the worker finally, so the claim must be returned separately.
    if not future.cancelled():
        return
    result = {"ok": False, "status": "failed", "error": "Task was canceled before it started running",
              "checked_at": datetime.now().isoformat(timespec="seconds")}
    try:
        db.update_account_plan_check(acc_id=account_id, result=result, expected_run_id=run_id)
    except Exception:
        logger.exception("Failed to write cancel status: account_id=%s", account_id)
    finally:
        with _LOCK:
            _RUNNING.discard(account_id)
        _QUEUE_SLOTS.release()


def _claim_plan_slot(account_id: int, trigger: str, *, run_id: str) -> dict | None:
    """The same claim logic is used for the manual queue and for synchronous queries within a liveness check session."""
    with _LOCK:
        if account_id in _RUNNING:
            return {"accepted": False, "busy": True, "error": "A plan query is already running for this account"}
        _RUNNING.add(account_id)
    if not _QUEUE_SLOTS.acquire(blocking=False):
        with _LOCK:
            _RUNNING.discard(account_id)
        return {"accepted": False, "busy": False, "queue_full": True, "error": "Plan query queue is full, please retry later"}

    try:
        claimed = db.claim_account_plan_check(acc_id=account_id, trigger=trigger, run_id=run_id)
    except Exception:
        with _LOCK:
            _RUNNING.discard(account_id)
        _QUEUE_SLOTS.release()
        raise
    if not claimed:
        with _LOCK:
            _RUNNING.discard(account_id)
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "A plan query is already running for this account"}

    return None


def check_account_plan_in_session(*, account_id: int, email: str, access_token: str, session) -> dict:
    """Run directly in the liveness check thread; it must not be submitted to the same stage pool and waited on (avoids thread pool deadlock)."""
    account_id = int(account_id)
    if session is None:
        return {"ok": False, "error": "Liveness check session does not exist, plan not queried"}
    if not str(access_token or "").strip():
        return {"ok": False, "error": "The account has no access_token"}
    run_id = uuid.uuid4().hex
    rejected = _claim_plan_slot(account_id, "live_auto", run_id=run_id)
    if rejected is not None:
        return {"ok": False, **rejected}
    return _run_plan_check(account_id=account_id, email=email, access_token=access_token,
                           trigger="live_auto", proxy=None, timezone_offset_min="-", session=session, run_id=run_id)


def enqueue_account_plan_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None = None,
    timezone_offset_min: str = "-",
    return_future: bool = False,
    executor: ThreadPoolExecutor | None = None,
) -> dict:
    """Put the query into the unified thread pool; do not submit on duplicate queries or a full queue."""
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not access_token:
        return {"accepted": False, "busy": False, "error": "The account has no access_token"}
    run_id = uuid.uuid4().hex
    rejected = _claim_plan_slot(account_id, trigger, run_id=run_id)
    if rejected is not None:
        return rejected

    try:
        future = (executor or _EXECUTOR).submit(
            _run_plan_check,
            account_id=account_id,
            email=email,
            access_token=access_token,
            trigger=str(trigger or "manual"),
            proxy=proxy,
            timezone_offset_min=str(timezone_offset_min or "-"),
            run_id=run_id,
        )
        future.add_done_callback(lambda done: _release_cancelled_check(done, account_id, run_id))
    except Exception as exc:
        with _LOCK:
            _RUNNING.discard(account_id)
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"Failed to enqueue plan query: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_plan_check(acc_id=account_id, result=result, expected_run_id=run_id)
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        **({"future": future} if return_future else {}),
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def queue_settings() -> dict:
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "min_interval": _float_setting("PLAN_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0),
        "jitter": _float_setting("PLAN_CHECK_JITTER", 0.3, 0.0, 30.0),
    }
