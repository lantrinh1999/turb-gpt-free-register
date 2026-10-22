# -*- coding: utf-8 -*-
"""Codex Agent Identity generation background queue."""
from __future__ import annotations

import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from config import proxy as proxy_cfg
from core import db
from core.session import close_browser_session

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _join_sub2_url(base: str, path: str) -> str:
    base = str(base or "").strip().rstrip("/")
    path = str(path or "").strip()
    if not base or not path:
        return ""
    parsed = urlparse(path)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return path
    return f"{base}/{path.lstrip('/')}"


def _sub2_codex_session_import_url() -> str:
    from config import sub2api as sub2api_cfg
    api_base = str(getattr(sub2api_cfg, "SUB2API_API_BASE", "") or "").strip()
    if api_base:
        return _join_sub2_url(api_base, "/api/v1/admin/accounts/import/codex-session")
    # Compatible with the old setting: SUB2API_API_URL used to be the full upload endpoint URL.
    return str(getattr(sub2api_cfg, "SUB2API_API_URL", "") or "").strip()


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(proxy_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("PLAN_CHECK_WORKERS", 3, 1, 16)
_QUEUE_LIMIT = _int_setting("PLAN_CHECK_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="codex-agent")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RATE_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(getattr(proxy_cfg, name, default) or 0.0)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _agent_request_settings() -> tuple[float, int, float]:
    """Reuse the timeout/retry config of the plan query."""
    timeout = _float_setting("PLAN_CHECK_TIMEOUT", 15.0, 1.0, 60.0)
    attempts = _int_setting("PLAN_CHECK_MAX_ATTEMPTS", 2, 1, 4)
    retry_delay = _float_setting("PLAN_CHECK_RETRY_DELAY", 1.5, 0.0, 30.0)
    return timeout, attempts, retry_delay


def _retryable_agent_error(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return (
        "429" in text
        or "408" in text
        or "409" in text
        or "425" in text
        or "500" in text
        or "502" in text
        or "503" in text
        or "504" in text
        or "timeout" in text
        or "timed out" in text
        or "connection" in text
        or "temporarily" in text
    )


def _wait_for_rate_slot() -> None:
    """Following the plan query: stagger the start times of Agent registration requests."""
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


def _safe_email_filename(email: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("@", ".", "-", "_") else "_" for ch in (email or "account"))


def _run_generate(*, account_id: int, email: str, access_token: str, trigger: str, verify_task: bool) -> dict:
    env = None
    relay = None
    route_meta: dict = {}
    timeout_seconds = 0.0
    attempts = 0
    attempt_count = 0
    try:
        if not db.mark_account_codex_agent_running(account_id):
            return {"ok": False, "error": "Account deleted or Codex Agent state has been reset"}
        from core.codex_agent import create_codex_agent_identity
        from core.chatgpt_plan import open_plan_check_proxy, resolve_plan_check_route
        from core.session import BrowserSession

        # Resolve the network path the same way as the plan check; create an independent BrowserSession per account,
        # so each gets its own oai-did / oai-session-id / Datadog trace / browser profile / proxy egress.
        route = resolve_plan_check_route(None)
        route_meta = {k: v for k, v in route.items() if k not in {"proxy", "upstream_proxy"}}
        timeout_seconds, attempts, retry_delay = _agent_request_settings()
        last_exc: Exception | None = None
        auth_json = None
        for attempt in range(1, attempts + 1):
            attempt_count = attempt
            _wait_for_rate_slot()
            try:
                effective_proxy, relay = open_plan_check_proxy(
                    route, route["proxy"], timeout=timeout_seconds,
                )
                env = BrowserSession(
                    proxy=effective_proxy,
                    detect_exit_geo=False,
                    fingerprint_seed=f"account:{email.lower()}:attempt:{attempt}",
                )
                logger.info(
                    "[CodexAgent] isolated environment: %s attempt=%s/%s route=%s proxy=%s did=%s session=%s profile_ua=%s",
                    email,
                    attempt,
                    attempts,
                    route_meta.get("network_route") or "-",
                    route_meta.get("proxy_used") or "-",
                    getattr(env, "device_id", "-"),
                    getattr(env, "oai_session_id", "-"),
                    str((getattr(env, "browser_profile", {}) or {}).get("user_agent") or "")[:60],
                )
                auth_json = create_codex_agent_identity(
                    access_token=access_token,
                    output_path=None,
                    verify_task=verify_task,
                    env=env,
                    timeout=timeout_seconds,
                )
                break
            except Exception as exc:
                last_exc = exc
                try:
                    close_browser_session(env)
                except Exception:
                    pass
                env = None
                if relay is not None:
                    relay.close()
                    relay = None
                if attempt >= attempts or not _retryable_agent_error(exc):
                    raise
                wait_seconds = min(30.0, retry_delay * attempt)
                logger.warning(
                    "[CodexAgent] generation failed temporarily, attempt %s/%s, retrying in %.1fs: %s: %s",
                    attempt,
                    attempts,
                    wait_seconds,
                    type(exc).__name__,
                    str(exc)[:180],
                )
                if wait_seconds > 0:
                    time.sleep(wait_seconds)
        if not isinstance(auth_json, dict):
            raise RuntimeError(f"Codex Agent generation did not return auth_json: {last_exc}")
        identity = auth_json.get("agent_identity") if isinstance(auth_json, dict) else {}
        sub2api_result = None
        try:
            from config import sub2api as sub2api_cfg
            if bool(getattr(sub2api_cfg, "SUB2API_AUTO_EXPORT", True)):
                from core.codex_agent import upsert_sub2api_account, upload_sub2api_account
                mode = str(getattr(sub2api_cfg, "SUB2API_SYNC_MODE", "api") or "api").strip().lower()
                if mode not in {"api", "file", "both"}:
                    logger.warning("[CodexAgent] SUB2API_SYNC_MODE=%s is invalid, treated as api", mode)
                    mode = "api"
                proxy_key = str(getattr(sub2api_cfg, "SUB2API_PROXY_KEY", "") or "").strip() or None

                results: list[dict] = []
                if mode in ("api", "both"):
                    api_url = _sub2_codex_session_import_url()
                    api_token = str(getattr(sub2api_cfg, "SUB2API_API_KEY", "") or getattr(sub2api_cfg, "SUB2API_API_TOKEN", "") or "").strip()
                    auth_header = str(getattr(sub2api_cfg, "SUB2API_API_AUTH_HEADER", "x-api-key") or "x-api-key").strip()
                    auth_prefix = str(getattr(sub2api_cfg, "SUB2API_API_AUTH_PREFIX", "") or "").strip()
                    payload_mode = "codex_session_import"
                    api_timeout = float(getattr(sub2api_cfg, "SUB2API_API_TIMEOUT", 20) or 20)
                    api_result = upload_sub2api_account(
                        auth_json,
                        api_url,
                        api_token=api_token,
                        auth_header=auth_header,
                        auth_prefix=auth_prefix,
                        payload_mode=payload_mode,
                        proxy_key=proxy_key,
                        timeout=api_timeout,
                    )
                    results.append({"mode": "api", **api_result})
                    logger.info(
                        "[CodexAgent] uploaded via API to sub2api: %s url=%s status=%s payload=%s",
                        email,
                        api_result.get("url"),
                        api_result.get("status_code"),
                        api_result.get("payload_mode"),
                    )

                if mode in ("file", "both"):
                    output = str(getattr(sub2api_cfg, "SUB2API_OUTPUT_PATH", "sub2api.json") or "sub2api.json").strip()
                    sub2api_output_path = Path(output)
                    if not sub2api_output_path.is_absolute():
                        sub2api_output_path = _PROJECT_ROOT / sub2api_output_path
                    file_result = upsert_sub2api_account(auth_json, sub2api_output_path, proxy_key=proxy_key)
                    results.append({"mode": "file", **file_result})
                    logger.info(
                        "[CodexAgent] synced to local sub2api: %s path=%s action=%s total=%s",
                        email,
                        file_result.get("path"),
                        "updated" if file_result.get("updated") else "added",
                        file_result.get("total"),
                    )

                sub2api_result = {
                    "ok": True,
                    "mode": mode,
                    "results": results,
                    "path": next((r.get("path") for r in results if r.get("path")), None),
                    "url": next((r.get("url") for r in results if r.get("url")), None),
                    "total": next((r.get("total") for r in results if r.get("total") is not None), None),
                }
        except Exception as sub_exc:
            logger.warning("[CodexAgent] Failed to sync sub2api (Agent Token is not affected): %s: %s", type(sub_exc).__name__, str(sub_exc)[:180])
        result = {
            "ok": True,
            "status": "success",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "message": "Codex Agent Token Generated" + (", synced to sub2api" if sub2api_result else ""),
            "agent_runtime_id": (identity or {}).get("agent_runtime_id"),
            "auth_path": None,
            "auth_json": auth_json,
            "sub2api_path": (sub2api_result or {}).get("path"),
            "sub2api_url": (sub2api_result or {}).get("url"),
            "sub2api_mode": (sub2api_result or {}).get("mode"),
            "sub2api_total": (sub2api_result or {}).get("total"),
            "network_route": route_meta.get("network_route"),
            "proxy_mode": route_meta.get("proxy_mode"),
            "proxy_used": route_meta.get("proxy_used"),
            "proxy_fallback_reason": route_meta.get("proxy_fallback_reason"),
            "attempt_count": attempt_count,
            "max_attempts": attempts,
            "request_timeout": timeout_seconds,
        }
        db.update_account_codex_agent(account_id, result)
        logger.info("[CodexAgent] generation succeeded: %s runtime=%s", email, result.get("agent_runtime_id") or "-")
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            "network_route": route_meta.get("network_route"),
            "proxy_mode": route_meta.get("proxy_mode"),
            "proxy_used": route_meta.get("proxy_used"),
            "proxy_fallback_reason": route_meta.get("proxy_fallback_reason"),
            "attempt_count": attempt_count,
            "max_attempts": attempts,
            "request_timeout": timeout_seconds,
        }
        try:
            db.update_account_codex_agent(account_id, result)
        except Exception:
            logger.exception("[CodexAgent] error while writing failure state: account_id=%s", account_id)
        logger.exception("[CodexAgent] Generation failed: %s", email)
        return result
    finally:
        if env is not None:
            try:
                close_browser_session(env)
            except Exception:
                pass
        if relay is not None:
            relay.close()
        _QUEUE_SLOTS.release()


def enqueue_account_codex_agent(*, account_id: int, email: str, access_token: str, trigger: str = "manual", verify_task: bool = True) -> dict:
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "error": "Codex Agent queue is full"}
    try:
        if not db.claim_account_codex_agent(account_id, trigger=trigger):
            _QUEUE_SLOTS.release()
            return {"accepted": False, "busy": True, "error": "This account is already generating Codex Agent Token"}
        fut = _EXECUTOR.submit(
            _run_generate,
            account_id=account_id,
            email=email,
            access_token=access_token,
            trigger=trigger,
            verify_task=verify_task,
        )
        return {"accepted": True, "busy": False, "future": fut}
    except Exception:
        _QUEUE_SLOTS.release()
        raise
