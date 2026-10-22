# -*- coding: utf-8 -*-
"""Account 2FA/TOTP background setup queue."""
from __future__ import annotations

import logging
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from config import email as _email_cfg
from config import twofa as _twofa_cfg
from core import db
from core.account_export import setup_2fa
from core.session import BrowserSession, close_browser_session
from core.proxy_utils import mask_proxy_url

logger = logging.getLogger(__name__)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(_twofa_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_MAX_WORKERS = 16
_WORKERS = _int_setting("TWOFA_WORKERS", 4, 1, _MAX_WORKERS)
_QUEUE_LIMIT = _int_setting("TWOFA_QUEUE_LIMIT", 200, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="twofa")
_RUNNING: set[int] = set()
_OUTSTANDING = 0
_LOCK = threading.Condition()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def apply_settings() -> dict:
    """Apply freshly loaded config values to the live queue service."""
    global _WORKERS, _QUEUE_LIMIT
    workers = _int_setting("TWOFA_WORKERS", 4, 1, _MAX_WORKERS)
    queue_limit = _int_setting("TWOFA_QUEUE_LIMIT", 200, workers, 5000)
    with _LOCK:
        _WORKERS = workers
        _QUEUE_LIMIT = queue_limit
        _LOCK.notify_all()
        return {
            "workers": _WORKERS,
            "queue_limit": _QUEUE_LIMIT,
            "running": len(_RUNNING),
            "outstanding": _OUTSTANDING,
        }


def _release_outstanding() -> None:
    global _OUTSTANDING
    with _LOCK:
        _OUTSTANDING = max(0, _OUTSTANDING - 1)
        _LOCK.notify_all()


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"twofa-{safe}.log"


def _normalize_proxy(proxy: str | None) -> str | None:
    """
    2FA entry only accepts real proxy addresses.

    Some `proxy_used` fields in the registration flow hold environment labels, e.g. `skyvern:jp`,
    `browser_use:jp`, such values are not proxies usable by curl_cffi and cause Unsupported proxy syntax.
    """
    text = str(proxy or "").strip()
    if not text:
        return None
    low = text.lower()
    if low.startswith(("http://", "https://", "socks5://", "socks5h://", "socks4://", "socks4a://")):
        return text
    return None


def _resolve_twofa_proxy(proxy: str | None):
    """Resolve the transport proxy according to TWOFA_PROXY_MODE."""
    mode = str(getattr(_twofa_cfg, "TWOFA_PROXY_MODE", "saved") or "saved").strip().lower()
    if mode not in {"saved", "pool"}:
        raise ValueError(f"TWOFA_PROXY_MODE={mode!r} is invalid, choose from saved / pool")
    if mode == "pool":
        from core.proxy_chain import open_proxy_pool_proxy
        transport, relay = open_proxy_pool_proxy(None)
        return transport or None, relay, "pool"
    target = _normalize_proxy(proxy)
    if not target:
        # When there is no reusable target proxy, leave it to BrowserSession to pick from the proxy pool;
        # BrowserSession manages the proxy-pool chained relay lifecycle itself.
        return None, None, "pool"
    from core.proxy_chain import open_proxy_pool_proxy

    transport, relay = open_proxy_pool_proxy(target)
    return transport, relay, "saved"


def is_running(acc_id: int) -> bool:
    with _LOCK:
        return int(acc_id) in _RUNNING


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _run_twofa(
    *, account_id: int, email: str, access_token: str, proxy: str | None,
    trigger: str,
) -> dict:
    global _OUTSTANDING
    fh: logging.FileHandler | None = None
    session: BrowserSession | None = None
    relay = None
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    try:
        with _LOCK:
            while len(_RUNNING) >= _WORKERS:
                _LOCK.wait()
            _RUNNING.add(int(account_id))
        if not db.mark_account_totp_setup_running(account_id):
            return {"ok": False, "status": "failed", "error": "Account deleted or 2FA state was reset"}
        log_file = log_path(email)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("", encoding="utf-8")
        fh = logging.FileHandler(str(log_path(email)), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)
        logger.info("[2FA] Background setup started:email=%s trigger=%s", email, trigger)
        real_proxy, relay, proxy_source = _resolve_twofa_proxy(proxy)
        identity = email.strip().lower()
        session = BrowserSession(proxy=real_proxy, fingerprint_seed=f"account:{identity}")
        target_label = mask_proxy_url(getattr(session, "proxy_target", None) or session.proxy or "direct") or "direct"
        transport_label = mask_proxy_url(session.proxy or "direct") or "direct"
        _append_log(
            email,
            f"[2FA] Session created:target={target_label} transport={transport_label} "
            f"source={proxy_source} device_id={session.device_id}",
        )
        _append_log(email, f"[2FA] Fingerprint summary:{session.fingerprint_summary_text()}")
        secret = setup_2fa(session, email, access_token=access_token)
        db.update_account_totp_secret(
            account_id,
            {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA setup completed"},
        )
        _append_log(email, f"[2FA] Done:secret={secret[:4]}...{secret[-4:]}")
        logger.info("[2FA] Done:email=%s secret=%s...%s", email, secret[:4], secret[-4:])
        return {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA setup completed"}
    except Exception as exc:
        result = {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
        try:
            db.update_account_totp_secret(account_id, result)
        except Exception:
            logger.exception("[2FA] Failed to write back failed state: account_id=%s", account_id)
        try:
            _append_log(email, f"[2FA] Failed:{result['error']}")
        except Exception:
            pass
        logger.exception("[2FA] Background error: %s", email)
        return result
    finally:
        if session is not None:
            try:
                close_browser_session(session)
            except Exception:
                pass
        if relay is not None:
            try:
                relay.close()
            except Exception:
                pass
        if fh is not None:
            try:
                root_logger.removeHandler(fh)
                fh.close()
            except Exception:
                pass
        with _LOCK:
            _RUNNING.discard(int(account_id))
            _OUTSTANDING = max(0, _OUTSTANDING - 1)
            _LOCK.notify_all()


def queue_settings() -> dict:
    apply_settings()
    with _LOCK:
        return {
            "workers": _WORKERS,
            "queue_limit": _QUEUE_LIMIT,
            "running": len(_RUNNING),
            "outstanding": _OUTSTANDING,
        }


def enqueue_account_totp_setup(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str = "manual",
    proxy: str | None = None,
) -> dict:
    global _OUTSTANDING
    apply_settings()
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email is empty"}
    if not access_token:
        return {"accepted": False, "busy": False, "error": "missing access_token"}
    if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
        return {"accepted": False, "busy": False, "error": "Enabling 2FA requires USE_EMAIL_SERVICE to be turned on first to receive email verification codes automatically"}
    with _LOCK:
        if _OUTSTANDING >= _QUEUE_LIMIT:
            return {"accepted": False, "busy": False, "queue_full": True, "error": "2FA queue is full, please try again later"}
        _OUTSTANDING += 1
    if not db.claim_account_totp_setup(acc_id=account_id, trigger=trigger):
        _release_outstanding()
        return {"accepted": False, "busy": True, "error": "This account is currently setting up 2FA"}

    _append_log(email, f"[2FA] Queued account_id={account_id} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(
            _run_twofa,
            account_id=account_id,
            email=email,
            access_token=access_token,
            proxy=proxy,
            trigger=str(trigger or "manual"),
        )
        return {"accepted": True, "busy": False, "future": future, "log_path": str(log_path(email))}
    except Exception as exc:
        _release_outstanding()
        db.update_account_totp_secret(account_id, {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        return {"accepted": False, "busy": False, "error": f"{type(exc).__name__}: {exc}"}
