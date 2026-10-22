# -*- coding: utf-8 -*-
"""Codex authorization rerun service, shared by the accounts page and the registration task queue."""
import ctypes
import logging
import threading
import time
from pathlib import Path

from core import db

logger = logging.getLogger(__name__)

_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"
_RETRYING: set[str] = set()
_RETRYING_LOCK = threading.Lock()
_STOP_REQUESTED: set[str] = set()
_RUNNING_THREADS: dict[str, int] = {}
_RESERVED_AT: dict[str, float] = {}


class CodexRetryStopped(Exception):
    """User manually stopped the Codex rerun."""


def _thread_alive(thread_id: int | None) -> bool:
    if not thread_id:
        return False
    try:
        tid = int(thread_id)
    except Exception:
        return False
    return any(getattr(t, "ident", None) == tid and t.is_alive() for t in threading.enumerate())


def _clear_state_locked(key: str) -> None:
    _RETRYING.discard(key)
    _RUNNING_THREADS.pop(key, None)
    _RESERVED_AT.pop(key, None)


def log_path(email: str) -> Path:
    safe = email.replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"codex-retry-{safe}.log"


def reserve(email: str) -> bool:
    """Prevent the same account from being rerun repeatedly within the process."""
    key = (email or "").strip().lower()
    if not key:
        return False
    with _RETRYING_LOCK:
        if key in _RETRYING:
            thread_id = _RUNNING_THREADS.get(key)
            alive = _thread_alive(thread_id)
            age = time.time() - float(_RESERVED_AT.get(key) or 0)
            stop_req = key in _STOP_REQUESTED
            try:
                acc = db.get_account_by_email(email)
                status = str((acc or {}).get("codex_status") or "").lower()
            except Exception:
                status = ""
            # Fix the inability to rerun again when the task is actually stopped / the thread has ended but the in-process placeholder was not released.
            # After the user clicks stop, some browser/SMS waiting steps may not exit immediately; the UI is already stopped but the process placeholder remains.
            # In this case the placeholder may be cleaned up and the rerun restarted; the old thread still keeps stop_requested and will exit at a checkpoint.
            terminal_status = status in {"stopped", "failed", "success", "deactivated", "skipped", "cancelled"}
            if ((not alive) and (status != "retrying" or age > 15 * 60)) or (terminal_status and (stop_req or age > 30)):
                logger.warning(
                    "[Codex rerun] Cleaning stale placeholder: email=%s status=%s thread_id=%s alive=%s stop_requested=%s age=%.1fs",
                    email, status or "-", thread_id or "-", alive, stop_req, age,
                )
                _clear_state_locked(key)
            else:
                return False
        _STOP_REQUESTED.discard(key)
        _RUNNING_THREADS.pop(key, None)
        _RETRYING.add(key)
        _RESERVED_AT[key] = time.time()
        return True


def release(email: str) -> None:
    key = (email or "").strip().lower()
    with _RETRYING_LOCK:
        _clear_state_locked(key)


def is_retrying(email: str) -> bool:
    with _RETRYING_LOCK:
        return (email or "").strip().lower() in _RETRYING


def is_stop_requested(email: str) -> bool:
    with _RETRYING_LOCK:
        return (email or "").strip().lower() in _STOP_REQUESTED


def check_stop_requested(email: str) -> None:
    if is_stop_requested(email):
        raise CodexRetryStopped("User manually stopped the Codex rerun")


def _async_raise(thread_id: int, exc_type: type[BaseException]) -> bool:
    """Inject an exception into the given Python thread to interrupt a blocked rerun flow as soon as possible."""
    if not thread_id:
        return False
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread_id),
        ctypes.py_object(exc_type),
    )
    if res == 0:
        return False
    if res != 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread_id), None)
        return False
    return True


def request_stop(email: str) -> dict:
    """Request to stop a single Codex rerun. A running one gets a stop exception injected; a queued one exits before starting."""
    key = (email or "").strip().lower()
    if not key:
        return {"ok": False, "error": "email is empty", "status": 400}
    with _RETRYING_LOCK:
        retrying = key in _RETRYING
        thread_id = _RUNNING_THREADS.get(key)
        _STOP_REQUESTED.add(key)
    if not retrying:
        db.update_account_codex_status(email, "stopped", "User manually stopped (no running rerun found)")
        return {"ok": True, "message": "No running rerun found, marked as stopped", "state": "stopped", "running": False}

    injected = bool(thread_id and _async_raise(int(thread_id), CodexRetryStopped))
    db.update_account_codex_status(email, "stopped", "User manually stopped the Codex rerun")
    # If there is no live thread to inject into, release the in-process placeholder immediately, to avoid the UI showing stopped while a new rerun still returns 409.
    with _RETRYING_LOCK:
        if not _thread_alive(thread_id):
            _clear_state_locked(key)
    if injected:
        # Exception injection usually makes the thread enter finally/release quickly; if browser/CDP/SMS waiting blocks the thread
        # from exiting within a short time, clean up the placeholder with a delay, to avoid the UI showing stopped while a new rerun still returns 409.
        def _delayed_release() -> None:
            time.sleep(5)
            with _RETRYING_LOCK:
                if key in _RETRYING and key in _STOP_REQUESTED:
                    try:
                        acc = db.get_account_by_email(email)
                        status = str((acc or {}).get("codex_status") or "").lower()
                    except Exception:
                        status = ""
                    if status == "stopped":
                        logger.warning("[Codex rerun] Delayed placeholder release after stop: email=%s thread_id=%s", email, thread_id or "-")
                        _clear_state_locked(key)

        threading.Thread(target=_delayed_release, name=f"codex-stop-release-{key}", daemon=True).start()
    try:
        p = log_path(email)
        p.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime as _dt
        with p.open("a", encoding="utf-8") as f:
            f.write(f"{_dt.now().strftime('%H:%M:%S')} [WARNING] [Codex rerun] User manually stopped, stop signal sent injected={injected}\n")
    except Exception:
        logger.exception("Failed to write the Codex stop log")
    return {"ok": True, "message": "Stop signal sent", "state": "stopped", "running": True, "injected": injected}


def run_worker(
    email: str,
    *,
    batch_label: str | None = None,
    clear_log: bool = True,
    target_log_path: str | Path | None = None,
) -> dict:
    """Run a Codex rerun once. reserve must be called first, and release happens automatically at the end."""
    fh: logging.FileHandler | None = None
    root_logger = logging.getLogger()
    result: dict = {"status": "failed", "ok": False, "message": "Codex rerun returned no result"}
    key = (email or "").strip().lower()
    try:
        with _RETRYING_LOCK:
            _RUNNING_THREADS[key] = threading.get_ident()
            _RESERVED_AT[key] = time.time()
        check_stop_requested(email)

        from core.codex_oauth import run_codex_oauth

        path = Path(target_log_path) if target_log_path else log_path(email)
        path.parent.mkdir(parents=True, exist_ok=True)
        if clear_log:
            path.write_text("", encoding="utf-8")

        thread_name = threading.current_thread().name
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)

        try:
            import config as config_pkg
            config_pkg.reload_all()
            from config import codex as codex_cfg
            from config import roxybrowser as roxy_cfg
            logger.info(
                "[Codex rerun] Config hot-reloaded:CODEX_OAUTH_DRIVER=%s ROXY_OPEN_HEADLESS=%s ROXY_KEEP_BROWSER_OPEN=%s",
                getattr(codex_cfg, "CODEX_OAUTH_DRIVER", ""),
                getattr(roxy_cfg, "ROXY_OPEN_HEADLESS", ""),
                getattr(roxy_cfg, "ROXY_KEEP_BROWSER_OPEN", ""),
            )
        except Exception as exc:
            logger.warning("[Codex rerun] Config hot reload failed, continuing with the current in-memory config:%s: %s", type(exc).__name__, exc)

        if batch_label:
            logger.info("[Codex rerun] Batch task:%s", batch_label)
        logger.info("[Codex rerun] Started:%s", email)
        logger.info("[Codex rerun] Stages: get authorization URL → log in to email → email OTP → phone verification → capture callback → submit/save credentials")
        check_stop_requested(email)
        result = run_codex_oauth(email, force=True)
        check_stop_requested(email)
        logger.info(
            "[Codex rerun] Result:status=%s ok=%s file=%s callback=%s",
            result.get("status"), result.get("ok"), result.get("file_path"), result.get("callback_url"),
        )
        result_status = result.get("status", "failed")
        if result.get("ok"):
            db.update_account_codex_status(email, "success", None)
            logger.info("[Codex rerun] %s succeeded", email)
        elif result_status == "deactivated":
            db.update_account_codex_status(email, "deactivated", result.get("message"))
            logger.warning("[Codex rerun] %s account deactivated: %s", email, result.get("message"))
        else:
            db.update_account_codex_status(email, result_status, result.get("message"))
            logger.warning("[Codex rerun] %s failed: %s", email, result.get("message"))
        return result
    except CodexRetryStopped as exc:
        result = {"status": "stopped", "ok": False, "message": str(exc) or "User manually stopped the Codex rerun"}
        db.update_account_codex_status(email, "stopped", result["message"])
        logger.warning("[Codex rerun] %s stopped: %s", email, result["message"])
        return result
    except Exception as exc:
        if is_stop_requested(email):
            result = {"status": "stopped", "ok": False, "message": "User manually stopped the Codex rerun"}
            db.update_account_codex_status(email, "stopped", result["message"])
            logger.warning("[Codex rerun] %s stopped", email)
            return result
        result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {exc}"}
        db.update_account_codex_status(email, "failed", result["message"])
        logger.exception("[Codex rerun] %s error", email)
        logger.error("[Codex rerun] Finished: failed with an error")
        return result
    finally:
        try:
            logger.info("[Codex rerun] Finished:%s", email)
            if fh is not None:
                root_logger.removeHandler(fh)
                fh.close()
        finally:
            release(email)
            with _RETRYING_LOCK:
                if key:
                    _STOP_REQUESTED.discard(key)
