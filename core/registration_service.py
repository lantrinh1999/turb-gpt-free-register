# -*- coding: utf-8 -*-
"""
Registration task service layer:
    - Thread-pool concurrent execution of run_registration
    - Each task has a record in data/registration_jobs.json
    - The log of each task is written to data/logs/<job_uuid>.log, convenient for the Web UI to tail in real time

Usage:
    submit_registration(email_source="outlook", count=5)
    → Create 5 tasks, throw them into the thread pool and return immediately [job_dict, ...]
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from core import codex_retry_service, db

logger = logging.getLogger(__name__)

# Global thread pool, maximum concurrency (the WebUI can rebuild it with the latest workers on every submit)
_DEFAULT_MAX_WORKERS = 4
_MIN_MAX_WORKERS = 1
_MAX_MAX_WORKERS = 16
_executor: ThreadPoolExecutor | None = None
_executor_workers = _DEFAULT_MAX_WORKERS
_executor_generation = 0
_retired_executors: list[ThreadPoolExecutor] = []
_executor_lock = threading.RLock()

_STOP_EVENTS: dict[int, threading.Event] = {}
_ACTIVE_JOBS: set[int] = set()
_STOP_LOCK = threading.Lock()
_THREAD_CTX = threading.local()


class StopRequested(RuntimeError):
    """The user manually stopped the registration task."""


def _activate_job(job_id: int) -> None:
    _THREAD_CTX.job_id = int(job_id)
    with _STOP_LOCK:
        _STOP_EVENTS.setdefault(int(job_id), threading.Event())
        _ACTIVE_JOBS.add(int(job_id))


def _deactivate_job(job_id: int) -> None:
    with _STOP_LOCK:
        _STOP_EVENTS.pop(int(job_id), None)
        _ACTIVE_JOBS.discard(int(job_id))
    try:
        delattr(_THREAD_CTX, "job_id")
    except Exception:
        pass


def is_stop_requested(job_id: int | None = None) -> bool:
    if job_id is None:
        job_id = getattr(_THREAD_CTX, "job_id", None)
    if not job_id:
        return False
    with _STOP_LOCK:
        ev = _STOP_EVENTS.get(int(job_id))
        if ev and ev.is_set():
            return True
    job = db.get_job(int(job_id))
    return bool(job and job.get("status") in ("stopping", "stopped", "cancelled"))


def check_stop_requested() -> None:
    job_id = getattr(_THREAD_CTX, "job_id", None)
    if is_stop_requested(job_id):
        raise StopRequested(f"Job #{job_id} was stopped by the user (manual stop)")


def _append_job_log(job_id: int, message: str) -> None:
    try:
        job = db.get_job(job_id)
        log_file = job.get("log_file") if job else None
        if not log_file:
            return
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%H:%M:%S")
        with Path(log_file).open("a", encoding="utf-8") as f:
            f.write(f"{ts} [WARNING] [manual-stop] {message}\n")
    except Exception:
        pass


def _random_display_name() -> str:
    """Generate an English-letter display name that satisfies the OpenAI restrictions."""
    from core.name_samples import random_display_name

    return random_display_name()


def _prepare_registration_args() -> tuple[str | None, str, str]:
    """Reuse the default rules of the CLI to fill in the registration parameters for the legacy Web task entry."""
    # Read through the module attribute to support WebUI hot reload
    from config import register as _r, email as _e
    from core.profile_utils import generate_random_birthday

    email = str(getattr(_r, "REGISTER_EMAIL", "") or "").strip()
    name = str(getattr(_r, "REGISTER_NAME", "") or "").strip()
    # WebUI/The config sometimes stores an empty value as "-"; this is not a valid OpenAI display name, so it is treated as empty and generated automatically
    if name in {"-", "—", "无", "空", "none", "None", "null", "NULL"}:
        name = ""

    if not name:
        # Manual mode also generates the display name automatically, reducing the configuration burden
        name = _random_display_name()

    birthday = generate_random_birthday()

    # An automatic email is not claimed in the preparation phase: the browser driver claims it after the page finds the email input box,
    # and the protocol driver claims it right when run_registration is about to start authentication. This way, when the page cannot be opened / the
    # input box cannot be found, no email order or pool material is consumed in advance.
    if not email and not _e.USE_EMAIL_SERVICE:
        raise RuntimeError(
            "Manual mode has no email configured. Please set REGISTER_EMAIL on the WebUI config page,"
            "or enable USE_EMAIL_SERVICE and claim one from the email pool."
        )

    return email, name, birthday


def _release_unconsumed_job_email(email: str | None, reason: str) -> None:
    """Task failure fallback: only reclaim email claims that have not produced an account and are still used."""
    if not email:
        return
    try:
        from core.email_provider import release_email_if_unconsumed

        release_email_if_unconsumed(email, note=f"Task not consumed, reclaimed automatically: {reason[:180]}")
    except Exception:
        logger.exception("[Service] Failed to reclaim the unconsumed email: %s", email)


def _is_final_session_access_token_timeout(error: object) -> bool:
    """
    Recognize the failure where the last registration step already returned /api/auth/session 200 but without an accessToken.
    Registering such an email again usually gets stuck in the same state, so the email pool entry is disabled directly as required.
    """
    text = str(error or "")
    if not text:
        return False
    return (
        "Timed out waiting for the /api/auth/session accessToken" in text
        and "WARNING_BANNER" in text
        and "'_http_status': 200" in text
    )


def _should_disable_failed_registration_email(error: object) -> bool:
    """Registration failure types that require disabling the email directly."""
    text = str(error or "")
    if not text:
        return False
    return (
        _is_final_session_access_token_timeout(text)
        or "After submitting the email it entered the login password page" in text
        or "auth.openai.com/log-in/password" in text
        or "/log-in/password" in text
    )


def _disable_job_email(email: str | None, reason: str) -> bool:
    """Disable the email of this task, to avoid claiming it again later."""
    if not email:
        return False
    try:
        from core.email_provider import release_email

        source = release_email(email, status="disabled", note=f"Auto-disabled: {reason[:180]}")
        logger.warning("[Service] Email disabled automatically: source=%s email=%s reason=%s", source, email, reason[:220])
        return True
    except Exception:
        logger.exception("[Service] Failed to disable the email automatically: %s", email)
        return False


def _normalize_workers(max_workers: int | None) -> int:
    if max_workers is None:
        return _DEFAULT_MAX_WORKERS
    try:
        value = int(max_workers)
    except (TypeError, ValueError):
        value = _DEFAULT_MAX_WORKERS
    return max(_MIN_MAX_WORKERS, min(_MAX_MAX_WORKERS, value))


def get_executor(max_workers: int | None = None) -> ThreadPoolExecutor:
    """Return the registration thread pool.

    The old logic only used max_workers when the thread pool was first created, and a later WebUI change of the thread count still reused
    the previous pool. Now: whenever the max_workers passed in differs from the current pool, a new pool is created immediately for
    newly submitted tasks; the old pool accepts no new tasks but keeps running the tasks already queued/running.
    """
    global _executor, _executor_workers, _executor_generation
    requested_workers = _normalize_workers(max_workers) if max_workers is not None else _executor_workers
    with _executor_lock:
        if _executor is None or requested_workers != _executor_workers:
            old_executor = _executor
            if old_executor is not None:
                # Tasks already submitted to the old pool are not cancelled; new tasks are simply no longer appended to the old pool.
                old_executor.shutdown(wait=False, cancel_futures=False)
                _retired_executors.append(old_executor)
                logger.info(
                    "[Service] Registration thread pool workers switched from %s to %s; the old pool keeps processing the queued tasks",
                    _executor_workers,
                    requested_workers,
                )
            _executor_workers = requested_workers
            _executor_generation += 1
            _executor = ThreadPoolExecutor(
                max_workers=requested_workers,
                thread_name_prefix=f"reg-worker-{_executor_generation}",
            )
    return _executor


def get_executor_workers() -> int:
    """The thread count that currently newly submitted registration tasks will use."""
    with _executor_lock:
        return _executor_workers


def shutdown_executor(wait: bool = True) -> None:
    global _executor
    with _executor_lock:
        executors = []
        if _executor is not None:
            executors.append(_executor)
            _executor = None
        executors.extend(_retired_executors)
        _retired_executors.clear()
    for ex in executors:
        ex.shutdown(wait=wait, cancel_futures=False)


# ============================================================
# Single task execution: redirect the log to a task-specific file
# ============================================================

class _JobLogContext:
    """Give the root logger of this thread an extra FileHandler, removed after the end."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.handler: logging.FileHandler | None = None

    def __enter__(self):
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
        self.handler = logging.FileHandler(self.log_path, encoding="utf-8")
        self.handler.setLevel(logging.INFO)
        self.handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        # Filter only for this thread - distinguished by thread name, to avoid polluting the logs of other tasks
        thread_name = threading.current_thread().name
        self.handler.addFilter(lambda r: r.threadName == thread_name)
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handler is not None:
            self.handler.close()
            logging.getLogger().removeHandler(self.handler)


def _run_one_job(job_id: int, log_file: str) -> None:
    """Single task entry point (this runs in the thread pool)."""
    log_logger = logging.getLogger(__name__)
    _activate_job(job_id)

    # Cancel check: the user may have clicked "cancel queued" while the task was queued, changing status to cancelled.
    # Since a Future already submitted to the thread pool cannot be withdrawn, it can only check itself right before really executing and skip cancelled ones.
    current = db.get_job(job_id)
    if not current:
        log_logger.info(f"[Job {job_id}] The task record has been deleted, skipping execution")
        _deactivate_job(job_id)
        return
    if current.get("status") == "cancelled":
        log_logger.info(f"[Job {job_id}] Cancelled by the user, skipping execution")
        _deactivate_job(job_id)
        return

    db.update_job(job_id, status="running", started_at=datetime.now().isoformat(timespec="seconds"))

    email: str | None = None
    try:
        with _JobLogContext(log_file):
            from main import run_registration
            log_logger.info(f"[Job {job_id}] Starting the registration task")
            email, name, birthday = _prepare_registration_args()
            db.update_job(job_id, email=email)
            check_stop_requested()
            def _on_email_acquired(acquired_email: str) -> None:
                nonlocal email
                email = str(acquired_email or "").strip() or None
                if email:
                    db.update_job(job_id, email=email)
                    log_logger.info(f"[Job {job_id}] The page found the email input box, email allocated: {email}")

            result = run_registration(
                email=email,
                name=name,
                birthday=birthday,
                on_email_acquired=_on_email_acquired,
            )
            if is_stop_requested(job_id):
                _release_unconsumed_job_email(email, "Manually stopped by the user")
                db.update_job(
                    job_id,
                    status="stopped",
                    network_traffic=(result or {}).get("network_traffic") if isinstance(result, dict) else None,
                    error="Manually stopped by the user",
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                log_logger.warning(f"[Job {job_id}] Stopped at the user request")
                return
            if isinstance(result, dict) and result.get("success"):
                db.update_job(
                    job_id,
                    status="success",
                    email=result.get("email"),
                    account_id=result.get("account_id"),
                    network_traffic=result.get("network_traffic"),
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                log_logger.info(f"[Job {job_id}] Success: {result.get('email')}")
            else:
                # Note: a failure may also come with an account_id (e.g. Codex failed but the account registered successfully)
                err = (result or {}).get("error") if isinstance(result, dict) else "unknown"
                result_email = (result or {}).get("email") if isinstance(result, dict) else None
                db.update_job(
                    job_id,
                    status="failed",
                    email=result_email,
                    account_id=(result or {}).get("account_id") if isinstance(result, dict) else None,
                    network_traffic=(result or {}).get("network_traffic") if isinstance(result, dict) else None,
                    error=str(err)[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                email_to_handle = str(result_email or email or "").strip()
                if _should_disable_failed_registration_email(err):
                    _disable_job_email(email_to_handle, str(err))
                else:
                    _release_unconsumed_job_email(email_to_handle, str(err))
                log_logger.error(f"[Job {job_id}] failed: {err}")
    except StopRequested as exc:
        _release_unconsumed_job_email(email, str(exc))
        log_logger.warning(f"[Job {job_id}] Stopped: {exc}")
        db.update_job(
            job_id,
            status="stopped",
            error="Manually stopped by the user",
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    except Exception as exc:
        err_text = f"{type(exc).__name__}: {exc}"
        if _should_disable_failed_registration_email(err_text):
            _disable_job_email(email, err_text)
        else:
            _release_unconsumed_job_email(email, err_text)
        if is_stop_requested(job_id):
            log_logger.warning(f"[Job {job_id}] Exception caught while stopping, handled as a stop: {type(exc).__name__}: {exc}")
            db.update_job(
                job_id,
                status="stopped",
                error="Manually stopped by the user",
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            return
        log_logger.exception(f"[Job {job_id}] Exception")
        db.update_job(
            job_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    finally:
        _deactivate_job(job_id)


def _run_codex_retry_job(job_id: int, log_file: str, email: str, account_id: int) -> None:
    """Run the Codex rerun as a standard task, reusing the task status, logs and stop entry."""
    _activate_job(job_id)
    current = db.get_job(job_id)
    if not current or current.get("status") == "cancelled":
        codex_retry_service.release(email)
        _deactivate_job(job_id)
        return

    db.update_job(job_id, status="running", started_at=datetime.now().isoformat(timespec="seconds"))
    try:
        result = codex_retry_service.run_worker(
            email,
            clear_log=False,
            target_log_path=log_file,
        )
        now_iso = datetime.now().isoformat(timespec="seconds")
        if is_stop_requested(job_id) or result.get("status") == "stopped":
            db.update_job(job_id, status="stopped", email=email, account_id=account_id, error=str(result.get("message") or "Manually stopped by the user")[:500], completed_at=now_iso)
        elif result.get("ok"):
            db.update_job(
                job_id,
                status="success",
                email=email,
                account_id=account_id,
                completed_at=now_iso,
            )
        else:
            db.update_job(
                job_id,
                status="failed",
                email=email,
                account_id=account_id,
                error=str(result.get("message") or "Codex rerun failed")[:500],
                completed_at=now_iso,
            )
    except Exception as exc:
        db.update_job(
            job_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        codex_retry_service.release(email)
        logger.exception("[Job %s] Codex rerun error", job_id)
    finally:
        _deactivate_job(job_id)


# ============================================================
# Public interface
# ============================================================

def submit_registration(count: int = 1, email_source: str | None = None, workers: int | None = None) -> list[dict]:
    """
    Create N registration tasks and submit them to the thread pool.
    email_source Only recorded in the DB; the actual email source is fixed to the Outlook account pool.

    Returns:
        N newly created job dict
    """
    if email_source is None:
        from config import email as _email_cfg
        email_source = _email_cfg.EMAIL_SOURCE

    # Creating/switching the thread pool and submitting this batch of tasks must be serialized as a whole: otherwise another request switching workers midway through the submit
    # and shutting down the old pool makes later submits fail with cannot schedule new futures after shutdown.
    with _executor_lock:
        executor = get_executor(max_workers=workers)
        effective_workers = get_executor_workers()
        jobs = []
        for _ in range(count):
            job = db.create_job(email_source=email_source)
            try:
                executor.submit(_run_one_job, job["id"], job["log_file"])
            except Exception as exc:
                db.update_job(
                    int(job["id"]),
                    status="failed",
                    error=f"Queue submit failed:{type(exc).__name__}: {exc}"[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                logger.exception("[Service] Registration task #%s failed to be submitted to the thread pool", job["id"])
            jobs.append(db.get_job(int(job["id"])) or job)
    logger.info(f"[Service] Submitted {count} registration tasks, source={email_source},workers={effective_workers}")
    return jobs


def _account_for_job(job: dict) -> dict | None:
    account_id = job.get("account_id")
    if account_id is not None:
        try:
            account = db.get_account(int(account_id))
            if account is not None:
                return account
        except (TypeError, ValueError):
            pass
    email = str(job.get("email") or "").strip()
    return db.get_account_by_email(email) if email else None


def get_retry_info(job: dict) -> dict:
    """Retry capability description returned to the API/UI, without relying on the front end guessing the error stage."""
    status = str(job.get("status") or "")
    info = {
        "retryable": False,
        "retry_action": None,
        "retry_label": None,
        "retry_reason": None,
        "display_status": status,
    }
    if status not in ("failed", "stopped", "cancelled"):
        return info

    successful_retry = db.get_successful_retry_for_job(int(job.get("id") or 0))
    if successful_retry is not None:
        info["retry_reason"] = f"Later retry task #{successful_retry.get('id')} already succeeded"
        info["successful_retry_job_id"] = successful_retry.get("id")
        return info

    account = _account_for_job(job)
    if account and job.get("account_id") is not None and status in ("failed", "stopped"):
        info["display_status"] = "success" if (account.get("codex_status") or "") == "success" else "partial_success"

    if account:
        codex_status = str(account.get("codex_status") or "")
        if codex_status == "deactivated":
            info["retry_reason"] = "The account is dead and cannot be rerun with Codex"
            return info
        if codex_status == "success":
            info["retry_reason"] = "The account and the Codex authorization are both completed"
            return info
        info.update({
            "retryable": True,
            "retry_action": "codex",
            "retry_label": "Rerun Codex",
        })
        return info

    info.update({
        "retryable": True,
        "retry_action": "registration",
        "retry_label": "Retry",
    })
    return info


def retry_job(job_id: int, workers: int | None = None) -> dict:
    """Smart retry of terminal-state tasks: re-register when no account was produced, only rerun Codex when an account exists."""
    source = db.get_job(job_id)
    if source is None:
        return {"ok": False, "error": "Task does not exist", "status": 404}

    retry_info = get_retry_info(source)
    if not retry_info["retryable"]:
        reason = retry_info.get("retry_reason") or f"The current state does not support retry:{source.get('status')}"
        return {"ok": False, "error": reason, "status": 409}

    action = str(retry_info["retry_action"])
    account = _account_for_job(source)
    email = str((account or {}).get("email") or source.get("email") or "").strip()
    account_id = int(account["id"]) if account and account.get("id") is not None else None
    reserved_codex = False
    if action == "codex":
        if not email or account_id is None:
            return {"ok": False, "error": "Registered account information is incomplete, cannot rerun Codex", "status": 409}
        if not codex_retry_service.reserve(email):
            return {"ok": False, "error": "The account is currently rerunning Codex, please wait", "status": 409}
        reserved_codex = True

    try:
        job, created = db.create_retry_job(
            int(job_id),
            job_type="codex_retry" if action == "codex" else "registration",
            email_source=str(source.get("email_source") or "outlook"),
            email=email if action == "codex" else None,
            account_id=account_id if action == "codex" else None,
        )
    except LookupError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 404}
    except ValueError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 409}

    if not created:
        if reserved_codex:
            codex_retry_service.release(email)
        return {
            "ok": True,
            "created": False,
            "reused": True,
            "message": f"There is already a retry task #{job['id']} is queued or running",
            "source_job_id": int(job_id),
            "retry_action": action,
            "job": job,
        }

    try:
        if action == "codex":
            db.update_account_codex_status(email, "retrying", None)
        with _executor_lock:
            executor = get_executor(max_workers=workers)
            if action == "codex":
                executor.submit(_run_codex_retry_job, job["id"], job["log_file"], email, int(account_id))
            else:
                executor.submit(_run_one_job, job["id"], job["log_file"])
    except Exception as exc:
        if reserved_codex:
            codex_retry_service.release(email)
            db.update_account_codex_status(email, "failed", f"Queue submit failed:{type(exc).__name__}: {exc}"[:500])
        db.update_job(
            int(job["id"]),
            status="failed",
            error=f"Queue submit failed:{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        logger.exception("[Service] Retry task #%s failed to be submitted to the thread pool", job["id"])
        return {"ok": False, "error": "The retry task was created, but submitting it for execution failed", "status": 500, "job": db.get_job(int(job["id"]))}

    return {
        "ok": True,
        "created": True,
        "reused": False,
        "message": f"Retry task created #{job['id']} ({'Codex Rerun' if action == 'codex' else 'full registration'})",
        "source_job_id": int(job_id),
        "retry_action": action,
        "job": job,
    }


def cancel_pending_jobs() -> int:
    """
    Batch change all tasks with status=pending to cancelled, so they are not executed.
    Tasks already running are left alone (they cannot be interrupted midway in the thread pool).
    Returns the number successfully cancelled.

    The real guarantee of "not executing" is at the start of _run_one_job - when it actually runs it first checks status to decide whether to skip.
    """
    jobs = db.list_jobs(limit=1000)
    cancelled = 0
    now_iso = datetime.now().isoformat(timespec="seconds")
    for job in jobs:
        if job.get("status") == "pending":
            db.update_job(
                int(job["id"]),
                status="cancelled",
                completed_at=now_iso,
                error="Manually cancelled by the user",
            )
            cancelled += 1
    logger.info(f"[Service] Cancelled {cancelled} queued tasks")
    return cancelled


def request_stop_job(job_id: int) -> dict:
    """Manually stop a single registration task. Pending ones are cancelled directly; for running ones a stop flag is set and the running thread exits at a checkpoint."""
    job = db.get_job(job_id)
    if not job:
        return {"ok": False, "error": "Task does not exist", "status": 404}
    status = job.get("status")
    now_iso = datetime.now().isoformat(timespec="seconds")
    if status == "pending":
        db.update_job(job_id, status="cancelled", completed_at=now_iso, error="Manually stopped / queue cancelled by the user")
        _append_job_log(job_id, "Manual stop: the task has not started running, the queue entry was cancelled.")
        return {"ok": True, "message": "Queued task cancelled", "job_id": job_id, "state": "cancelled"}
    if status in ("success", "failed", "cancelled", "stopped"):
        return {"ok": True, "message": f"Task already finished:{status}", "job_id": job_id, "state": status}
    if status in ("running", "stopping"):
        with _STOP_LOCK:
            active = int(job_id) in _ACTIVE_JOBS
            ev = _STOP_EVENTS.get(int(job_id)) if active else None
            if ev is not None:
                ev.set()
        if not active or ev is None:
            # Web Service restart, abnormal thread exit, a historical leftover stopping, or an earlier manual stop only created the stop event
            # but no real thread instance: set it straight to stopped, to avoid being stuck at "stopping" forever.
            with _STOP_LOCK:
                _STOP_EVENTS.pop(int(job_id), None)
                _ACTIVE_JOBS.discard(int(job_id))
            db.update_job(
                job_id,
                status="stopped",
                completed_at=now_iso,
                error="Manually stopped by the user (task instance does not exist)",
            )
            _release_unconsumed_job_email(
                str(job.get("email") or "").strip() or None,
                "Task instance does not exist, confirmed not to be executing any more",
            )
            _append_job_log(job_id, "Manual stop: no running task instance found, directly marked as stopped.")
            logger.warning("[Service] User stopped task #%s: the task instance does not exist, directly marked stopped", job_id)
            return {"ok": True, "message": "Task instance does not exist, directly marked as stopped", "job_id": job_id, "state": "stopped"}
        db.update_job(job_id, status="stopping", error="Manual stop in progress")
        _append_job_log(job_id, "Manual stop: the stop signal was sent, the task exits at the checkpoint of the current step.")
        logger.warning("[Service] User requested to stop the task #%s", job_id)
        return {"ok": True, "message": "Stop signal sent", "job_id": job_id, "state": "stopping"}
    return {"ok": False, "error": f"The current state does not support stopping:{status}", "status": 409}


def read_job_log(job_id: int, max_bytes: int = 50_000) -> str:
    """Read the last max_bytes bytes of the task log file, to show in the Web UI."""
    job = db.get_job(job_id)
    if not job or not job.get("log_file"):
        return ""
    p = Path(job["log_file"])
    if not p.exists():
        return ""
    size = p.stat().st_size
    with p.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        data = f.read()
    return data.decode("utf-8", errors="replace")
