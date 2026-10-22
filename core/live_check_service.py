# -*- coding: utf-8 -*-
"""Account liveness check background queue: protocol BrowserSession fingerprint environment + separate logs."""
from __future__ import annotations

import logging
import random
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from core import db
from core.account_liveness import check_account_liveness, log_path
from core.chatgpt_plan import _mask_proxy, open_plan_check_proxy, resolve_plan_check_route

logger = logging.getLogger(__name__)

_WORKERS = 3
_QUEUE_LIMIT = 500
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="live-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_NETWORK_RETRY_HINTS = (
    "403", "429", "502", "503", "504", "proxy", "socks", "timeout",
    "timed out", "connection", "closed", "reset",
)


def _configured_live_check_proxies(proxy_cfg) -> list[str]:
    """Liveness check prefers the dedicated plan proxy pool, and falls back to the registration proxy pool when it is not configured."""
    values = list(getattr(proxy_cfg, "PLAN_CHECK_PROXY", []) or [])
    if not values:
        values = list(getattr(proxy_cfg, "PROXY_POOL", []) or [])
    return [str(value).strip() for value in values if str(value).strip()]


def _live_proxy_route(proxy_url: str, proxy_cfg) -> dict:
    route = resolve_plan_check_route(explicit_proxy=proxy_url)
    upstream = str(getattr(proxy_cfg, "PLAN_CHECK_UPSTREAM_PROXY", "") or "").strip()
    if upstream:
        route["upstream_proxy"] = upstream
        route["upstream_proxy_used"] = _mask_proxy(upstream) or None
        route["network_route"] = "proxy_chain"
    route["proxy_mode"] = "proxy_pool"
    return route


def _retryable_live_check_result(result: dict) -> bool:
    if result.get("ok") or result.get("status") == "deactivated":
        return False
    text = str(result.get("error") or "").lower()
    return any(hint in text for hint in _NETWORK_RETRY_HINTS)


def is_checking(email: str) -> bool:
    acc = db.get_account_by_email(email)
    if not acc:
        return False
    with _LOCK:
        if int(acc["id"]) in _RUNNING:
            return True
    return str(acc.get("live_check_status") or "") in {"queued", "running"}


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _safe_append_log(email: str, line: str, *, clear: bool = False) -> None:
    """Failure of auxiliary logging must not override the liveness check result or prevent saving the refreshed AT."""
    try:
        _append_log(email, line, clear=clear)
    except Exception:
        logger.warning("[Liveness check] failed to write log: %s", email, exc_info=True)


def _close_relay(relay) -> None:
    if relay is not None:
        try:
            relay.close()
        except Exception:
            logger.warning("[Liveness check] failed to close proxy relay", exc_info=True)


def complete_authenticated_live_check(*, account_id: int, expected_account: dict, result: dict, session, run_id: str | None = None) -> dict:
    """Persist the new AT first, then reuse the login session to query the plan; a plan failure does not change a successful liveness check."""
    if not db.update_account_liveness(account_id, result, expected_account=expected_account, expected_run_id=run_id):
        return {"ok": False, "status": "failed", "error": "Account deleted or email/AT changed, discarding the stale liveness check result"}
    try:
        from core.plan_check_service import check_account_plan_in_session
        result["plan_result"] = check_account_plan_in_session(
            account_id=account_id, email=expected_account["email"],
            access_token=result["access_token"], session=session,
        )
    except Exception as exc:
        logger.exception("[Liveness check] auto plan query error: account_id=%s", account_id)
        result["plan_result"] = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    _safe_append_log(expected_account["email"], "[Liveness check] auto plan query:" +
                     ("Success" if result["plan_result"].get("ok") else "failed " + str(result["plan_result"].get("error") or "")))
    return result


def _run_live_check(*, account_id: int, email: str, proxy: str | None, trigger: str, run_id: str | None = None) -> dict:
    relay = None
    expected_account = {"email": email}
    completed_in_session = False
    def authenticated(result, session):
        nonlocal completed_in_session
        completed = complete_authenticated_live_check(account_id=account_id, expected_account=expected_account,
                                                       result=result, session=session, run_id=run_id)
        # The callback is considered handled only if it returns normally; if saving the AT raises an error, the final failed state still has to be persisted.
        completed_in_session = True
        return completed
    try:
        with _LOCK:
            _RUNNING.add(int(account_id))
        if not db.mark_account_live_check_running(account_id, run_id=run_id):
            _safe_append_log(email, "[Liveness check] account deleted or liveness check state was reset, cancelling execution")
            return {"ok": False, "status": "failed", "error": "Account deleted or liveness check state was reset"}
        from config import proxy as proxy_cfg
        candidates = _configured_live_check_proxies(proxy_cfg)
        route = resolve_plan_check_route(explicit_proxy=proxy)
        # The liveness check rule is independent of the direct/auto choice of the plan query: as long as any proxy pool has entries,
        # direct connection is forbidden and one egress is picked at random from the pool.
        if candidates and not str(route.get("proxy") or "").strip():
            route = _live_proxy_route(random.choice(candidates), proxy_cfg)
        selected_proxy = str(route.get("proxy") or "").strip()
        timeout = float(getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0) or 15.0)
        # The liveness check must reuse the email source recorded when the account was registered. It cannot just call
        # resolve_email_source(email): the context of temporary mailboxes such as Remail only exists in the memory of the process that claimed it,
        # and after a service restart, inferring from the current EMAIL_SOURCE would get the source wrong.
        account = db.get_account(account_id) or {}
        if not account or str(account.get("email") or "").strip().lower() != email.strip().lower():
            result = {"ok": False, "status": "failed", "error": "Account deleted or email changed, discarding the stale liveness check task"}
            db.update_account_liveness(account_id, result, expected_account=expected_account, expected_run_id=run_id)
            return result
        expected_account = {"email": email, "access_token": account.get("access_token", "")}
        email_source = str(account.get("email_source") or "").strip() or None
        if email_source:
            _safe_append_log(email, f"[Liveness check] using the email source saved at registration:{email_source}")
        _safe_append_log(
            email,
            "[Liveness check] starting background execution "
            f"trigger={trigger} network_route={route.get('network_route')} "
            f"proxy_mode={route.get('proxy_mode')} proxy_used={route.get('proxy_used') or '-'} "
            f"fallback_reason={route.get('proxy_fallback_reason') or '-'}"
        )
        # Each proxy egress uses its own BrowserSession/fingerprint/Cookie. After a network-type failure, switch to an
        # unused proxy from the pool; never connect directly when the pool is non-empty.
        max_routes = max(1, int(getattr(proxy_cfg, "PLAN_CHECK_MAX_ATTEMPTS", 3) or 3))
        used_proxies: set[str] = set()
        result: dict = {"ok": False, "status": "failed", "error": "Liveness check not executed"}
        for route_attempt in range(1, max_routes + 1):
            selected_proxy = str(route.get("proxy") or "").strip()
            if selected_proxy:
                used_proxies.add(selected_proxy)
            effective_proxy, relay = open_plan_check_proxy(
                route, selected_proxy, timeout=timeout,
            )
            _safe_append_log(
                email,
                f"[Liveness check] network egress attempt {route_attempt}/{max_routes}:"
                f"{_mask_proxy(selected_proxy) or 'direct'}",
            )
            # The slot belongs to this egress attempt and must not reuse the completion flag of the previous failed callback.
            completed_in_session = False
            result = check_account_liveness(
                email,
                proxy=effective_proxy,
                clear_log=False,
                email_source=email_source,
                fingerprint_state={"force_fresh": route_attempt > 1},
                on_authenticated=authenticated,
            )
            if relay is not None:
                _close_relay(relay)
                relay = None
            if not _retryable_live_check_result(result):
                break

            remaining = [item for item in candidates if item not in used_proxies]
            if remaining and route_attempt < max_routes:
                next_proxy = random.choice(remaining)
                _safe_append_log(
                    email,
                    "[Liveness check] network/403 error on the current proxy, abandoning this session and randomly switching to the next proxy:"
                    f"{_mask_proxy(next_proxy)}",
                )
                route = _live_proxy_route(next_proxy, proxy_cfg)
                continue

            if candidates:
                break

            # When there is no proxy pool data at all, keep the original one-time direct connection fallback behavior.
            if selected_proxy and route_attempt < max_routes:
                _safe_append_log(
                    email,
                    "[Liveness check] no replaceable proxy configured, starting an independent direct session as a one-time fallback",
                )
                route = resolve_plan_check_route(explicit_proxy="")
                continue
            break
        if not completed_in_session and not db.update_account_liveness(account_id, result, expected_account=expected_account, expected_run_id=run_id):
            return {"ok": False, "status": "failed", "error": "Account deleted or email/AT changed, discarding the stale liveness check result"}
        if result.get("ok"):
            _safe_append_log(email, "[Liveness check] done: account is healthy, latest refreshed AT/accessToken")
        elif result.get("status") == "deactivated":
            _safe_append_log(email, f"[Liveness check] done: account is dead {result.get('error') or ''}")
        else:
            _safe_append_log(email, f"[Liveness check] done: failed {result.get('error') or ''}")
        result.update({
            "network_route": route.get("network_route"),
            "proxy_used": _mask_proxy(selected_proxy) or None,
            "upstream_proxy_used": route.get("upstream_proxy_used"),
            "proxy_mode": route.get("proxy_mode"),
            "proxy_fallback_reason": route.get("proxy_fallback_reason"),
        })
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
        }
        try:
            db.update_account_liveness(account_id, result, expected_account=expected_account, expected_run_id=run_id)
        except Exception:
            logger.exception("[Liveness check] failed to write error state: account_id=%s", account_id)
        logger.exception("[Liveness check] background error: %s", email)
        try:
            _safe_append_log(email, f"[Liveness check] background error:{result['error']}")
        except Exception:
            pass
        return result
    finally:
        try:
            if relay is not None:
                _close_relay(relay)
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
        db.update_account_liveness(account_id, result, expected_run_id=run_id)
    except Exception:
        logger.exception("Failed to write cancel status: account_id=%s", account_id)
    finally:
        with _LOCK:
            _RUNNING.discard(account_id)
        _QUEUE_SLOTS.release()


def enqueue_account_live_check(*, account_id: int, email: str, trigger: str = "manual", proxy: str | None = None, return_future: bool = False, executor: ThreadPoolExecutor | None = None) -> dict:
    account_id = int(account_id)
    email = str(email or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email is empty"}
    with _LOCK:
        if account_id in _RUNNING:
            return {"accepted": False, "busy": True, "error": "This account is being liveness-checked"}
        _RUNNING.add(account_id)
    if not _QUEUE_SLOTS.acquire(blocking=False):
        with _LOCK:
            _RUNNING.discard(account_id)
        return {"accepted": False, "busy": False, "queue_full": True, "error": "Liveness check queue is full, please try again later"}
    run_id = uuid.uuid4().hex
    try:
        claimed = db.claim_account_live_check(acc_id=account_id, trigger=trigger, run_id=run_id, expected_email=email)
    except Exception:
        with _LOCK:
            _RUNNING.discard(account_id)
        _QUEUE_SLOTS.release()
        raise
    if not claimed:
        with _LOCK:
            _RUNNING.discard(account_id)
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "This account is being liveness-checked"}

    try:
        _append_log(email, f"[Liveness check] queued account_id={account_id} trigger={trigger}", clear=True)
        future = (executor or _EXECUTOR).submit(
            _run_live_check,
            account_id=account_id,
            email=email,
            proxy=proxy,
            trigger=str(trigger or "manual"),
            run_id=run_id,
        )
        future.add_done_callback(lambda done: _release_cancelled_check(done, account_id, run_id))
    except Exception as exc:
        with _LOCK:
            _RUNNING.discard(account_id)
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"Failed to queue liveness check: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_liveness(account_id, result, expected_run_id=run_id)
        try:
            _append_log(email, result["error"])
        except Exception:
            logger.exception("[Liveness check] error while writing the enqueue failure log")
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
    return {"workers": _WORKERS, "queue_limit": _QUEUE_LIMIT}
