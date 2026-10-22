# -*- coding: utf-8 -*-
"""ChatGPT Background queue for account email changes."""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from core import db
from core.email_provider import (
    acquire_email_from_source, email_material_line,
    release_email_if_unconsumed, wait_for_otp,
)
from core.session import BrowserSession, close_browser_session

logger = logging.getLogger(__name__)
_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="email-change")
_SLOTS = threading.BoundedSemaphore(100)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def log_path(account_id: int) -> Path:
    return _LOG_DIR / f"email-change-{int(account_id)}.log"


def _append_log(account_id: int, message: str, *, clear: bool = False) -> None:
    path = log_path(account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if clear else "a"
    with path.open(mode, encoding="utf-8") as fh:
        fh.write(f"{datetime.now().strftime('%H:%M:%S')} [INFO] {message}\n")


def _proxy(value: str | None) -> str:
    text = str(value or "").strip()
    return text if text.lower().startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://")) else ""


def _proxy_label(value: str | None) -> str:
    """Proxy summary for logs: keeps the route information but hides the authentication password."""
    text = str(value or "").strip()
    if not text:
        return "direct"
    try:
        parsed = urlparse(text)
        auth = "***:***@" if parsed.username or parsed.password else ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{auth}{parsed.hostname or '?'}{port}"
    except Exception:
        return "proxy://***"


def _cost(started: float) -> str:
    return f"{time.monotonic() - started:.2f}s"


def _new_session(account_id: int, proxy, *, email: str = "") -> BrowserSession:
    # Uses the account-level seed, same as 2FA / liveness checks. For sensitive operations on the same account, device_id,
    # Sentinel sid and the browser profile stay stable, instead of creating a new device fingerprint just for the "email change".
    seed = f"account:{email.lower()}" if email else f"email-change:{account_id}"
    return BrowserSession(proxy=proxy, fingerprint_seed=seed)


def _response_error(resp) -> str:
    try:
        data = resp.json()
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            return str(err.get("message") or err.get("code") or data)
        return str(err or data)
    except Exception:
        return str(getattr(resp, "text", "") or f"HTTP {resp.status_code}")[:500]


def _is_reauth_required(exc: BaseException) -> bool:
    text = str(exc or "").lower()
    return "reauth_required" in text or "recent login required" in text


def _post(session: BrowserSession, path: str, token: str, payload: dict) -> dict:
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers.update({
        "authorization": f"Bearer {token}", "oai-device-id": session.device_id,
        "oai-language": session.navigator_language(), "origin": "https://chatgpt.com",
    })
    resp = session.post(f"https://chatgpt.com{path}", headers=headers, data=json.dumps(payload))
    if resp.status_code != 200:
        raise RuntimeError(f"{path} Return {resp.status_code}: {_response_error(resp)}")
    data = resp.json()
    if not isinstance(data, dict) or not data.get("success"):
        raise RuntimeError(f"{path} returned failure: {data}")
    return data


def _post_with_network_retry(
    session: BrowserSession, *, account_id: int, path: str, token: str, payload: dict,
    fingerprint_email: str = "",
) -> tuple[dict, BrowserSession]:
    """TLS reset/On transport failures such as timeouts, switch sessions and retry; the last attempt explicitly falls back to a direct connection."""
    last_exc: Exception | None = None
    current = session
    for attempt in range(1, 4):
        attempt_started = time.monotonic()
        _append_log(
            account_id,
            f"HTTP request started:path={path} attempt={attempt}/3 "
            f"route={_proxy_label(getattr(current, 'proxy', None))} "
            f"device_id={str(getattr(current, 'device_id', '') or '')[:12]}...",
        )
        try:
            result = _post(current, path, token, payload)
            _append_log(
                account_id,
                f"HTTP request succeeded:path={path} status=200 attempt={attempt}/3 cost={_cost(attempt_started)}",
            )
            return result, current
        except Exception as exc:
            last_exc = exc
            text = str(exc)
            _append_log(
                account_id,
                f"HTTP Request failed:path={path} attempt={attempt}/3 cost={_cost(attempt_started)} "
                f"error={type(exc).__name__}: {text[:300]}",
            )
            # Clear business 4xx errors are not resubmitted; only network errors, 429 and 5xx are retried.
            if isinstance(exc, RuntimeError) and "Return 4" in text and "Return 429" not in text:
                raise
            if attempt >= 3:
                break
            delay = attempt * 2
            next_route = "new proxy-pool session" if attempt == 1 else "direct connection fallback"
            _append_log(
                account_id,
                f"Request error (attempt {attempt}/3): {type(exc).__name__}: {text[:300]};"
                f"{delay}s switching to {next_route} and retrying afterwards",
            )
            logger.warning("[Email Change] %s attempt=%s failed: %s", path, attempt, text[:300])
            time.sleep(delay)
            # The second attempt re-selects the exit from the proxy pool; the third explicitly connects directly, so a bad proxy cannot keep resetting.
            current = _new_session(
                account_id, None if attempt == 1 else "", email=fingerprint_email,
            )
    assert last_exc is not None
    raise last_exc


def _enqueue_live_check_after_change(account_id: int, email: str) -> dict:
    """After a successful email change, immediately queue a liveness check, log in again with the new email and refresh the expired AT."""
    from core import live_check_service

    result = live_check_service.enqueue_account_live_check(
        account_id=int(account_id), email=str(email),
        trigger="email_change_auto", proxy=None,
    )
    if result.get("accepted"):
        logger.info("[email change] Automatically added to the liveness check queue account_id=%s email=%s", account_id, email)
        _append_log(account_id, f"Automatic liveness check queued:email={email}")
    else:
        logger.warning(
            "[email change] Email change succeeded, but queuing the automatic liveness check failed account_id=%s email=%s error=%s",
            account_id, email, result.get("error") or "Unknown error",
        )
        _append_log(account_id, f"Failed to queue the automatic liveness check:{result.get('error') or 'Unknown error'}")
    return result


def _refresh_recent_login(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> tuple[BrowserSession, str]:
    """Log in again following the complete login chain of the liveness check, establishing a Recent Login recognized by the server.

    change_email The reauth chain sends an OTP to the original email unconditionally, even if the account already has a saved
    registration password. Here it reuses the backup login chain of the liveness check instead: password first (and TOTP), and the original email OTP is only read when
    the login page really requires email verification.
    """
    # Lazy import, to avoid a module cycle when account_liveness initializes.
    from core.account_liveness import (
        _login_via_password_or_otp,
        _network_preflight_with_retry,
    )
    from core.openai_auth import (
        AccountUnusableError,
        detect_account_unusable_text,
        follow_authorize,
    )

    _append_log(
        account_id,
        "Recent Login Start: reuse the liveness check re-login logic (CSRF -> signin -> authorize -> password/OTP/MFA -> OAuth callback -> session/AT)",
    )

    # Keep the account-level device identity and browser profile already generated for this email change, while letting the liveness pre-check
    # create a clean login Cookie Jar and gain its network retry capability.
    fingerprint_state = {
        "fingerprint_seed": f"account:{email.lower()}",
    }
    for key in (
        "device_id", "auth_session_logging_id", "oai_session_id", "sentinel_sid",
    ):
        value = str(getattr(session, key, "") or "").strip()
        if value:
            fingerprint_state[key] = value
    browser_profile = getattr(session, "browser_profile", None)
    if isinstance(browser_profile, dict):
        fingerprint_state["browser_profile"] = dict(browser_profile)

    login_started = time.monotonic()
    selected_proxy = getattr(session, "proxy", None)
    # Same as the background liveness check: as soon as the full authentication chain on the proxy route receives a 403, it is rerun with a completely
    # independent direct session. A 403 on the OAuth callback puts the current BrowserSession
    # into a 15-minute circuit breaker; merely clearing the breaker and continuing neither fixes the exit nor avoids reusing the
    # contaminated CF Cookie, so the login must restart from CSRF.
    routes = [(selected_proxy, fingerprint_state, "current proxy route")]
    if selected_proxy:
        routes.append(("", {}, "independent direct fallback"))

    last_exc: BaseException | None = None
    for route_index, (route_proxy, route_state, route_label) in enumerate(routes):
        login_session: BrowserSession | None = None
        try:
            _append_log(account_id, f"Recent Login route started:{route_label}")
            login_session, authorize_url = _network_preflight_with_retry(
                email,
                route_proxy,
                fingerprint_state=route_state,
            )
            otp_after_ts = time.time()
            final_url = follow_authorize(login_session, authorize_url)
            dead_code = detect_account_unusable_text(final_url)
            if dead_code:
                raise AccountUnusableError(
                    f"Account is dead ({dead_code})",
                    error_code=dead_code,
                )
            info = _login_via_password_or_otp(
                login_session,
                email,
                otp_after_ts,
                email_source=email_source or None,
            )
            fresh_token = str((info or {}).get("accessToken") or "").strip()
            if not fresh_token:
                raise RuntimeError("Recent Login Re-login completed, but no new access_token")
            _append_log(
                account_id,
                f"Recent Login Completed: route={route_label}, obtained a fresh AT,cost={_cost(login_started)}",
            )
            return login_session, fresh_token
        except AccountUnusableError:
            raise
        except Exception as exc:
            last_exc = exc
            is_proxy_403 = route_index == 0 and bool(selected_proxy) and "403" in str(exc)
            if not is_proxy_403:
                raise
            _append_log(
                account_id,
                "Recent Login The proxy route received a 403 / session circuit breaker,"
                f"closing the failed session and starting from CSRF with the independent direct fallback:{type(exc).__name__}: {str(exc)[:260]}",
            )
            if login_session is not None:
                try:
                    close_browser_session(login_session)
                except Exception:
                    pass

    assert last_exc is not None
    raise last_exc


def _begin_change_with_optional_reauth(
    session: BrowserSession,
    *,
    account_id: int,
    current_email: str,
    current_source: str,
    new_email: str,
    access_token: str,
) -> tuple[BrowserSession, str, float, bool]:
    """Call begin directly first; verify the original email only when the server explicitly requires a Recent Login."""
    otp_after_ts = time.time()
    try:
        _, session = _post_with_network_retry(
            session,
            account_id=account_id,
            path="/backend-api/accounts/change_email/begin",
            token=access_token,
            payload={"email": new_email},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "The existing AT satisfies the Recent Login requirement, original email OTP re-authentication skipped")
        return session, access_token, otp_after_ts, False
    except Exception as exc:
        if not _is_reauth_required(exc):
            raise

    _append_log(account_id, "The server returned reauth_required, starting to log in again to the original account following the liveness check logic")
    session, fresh_token = _refresh_recent_login(
        session,
        account_id=account_id,
        email=current_email,
        email_source=current_source,
    )
    # The time baseline of the new email OTP must be set before the second begin, and must not reuse the time from before the re-authentication.
    otp_after_ts = time.time()
    _, session = _post_with_network_retry(
        session,
        account_id=account_id,
        path="/backend-api/accounts/change_email/begin",
        token=fresh_token,
        payload={"email": new_email},
        fingerprint_email=current_email,
    )
    _append_log(account_id, "Re-login to the original account completed, retrying begin with the fresh AT succeeded")
    return session, fresh_token, otp_after_ts, True


def _check_live_in_current_session(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> dict:
    """After the email change, log in again in the current session that already passed CF/reauth and refresh the AT."""
    from core.account_liveness import (
        _login_via_password_or_otp,
        _safe_fingerprint_for_account,
        _safe_fingerprint_text_for_account,
    )
    from core.chatgpt_auth import get_csrf_token, signin_openai
    from core.openai_auth import follow_authorize

    from core.live_check_service import complete_authenticated_live_check
    expected_account = db.get_account(account_id)
    if not expected_account or str(expected_account.get("email") or "").lower() != email.lower():
        raise RuntimeError("Account was deleted or its email changed, cancelling the original-session liveness check")
    live_started = time.monotonic()
    _append_log(account_id, "Original-session liveness check started: reusing Cookies, CF state, exit and the current fingerprint")
    step_started = time.monotonic()
    csrf = get_csrf_token(session)
    _append_log(account_id, f"Original-session liveness check: CSRF obtained successfully,cost={_cost(step_started)}")
    step_started = time.monotonic()
    authorize_url = signin_openai(session, csrf, email)
    _append_log(account_id, f"Original-session liveness check: signin succeeded and the authorize URL was obtained,cost={_cost(step_started)}")
    otp_after_ts = time.time()
    step_started = time.monotonic()
    follow_authorize(session, authorize_url)
    _append_log(account_id, f"Original-session liveness check: authorize followed, entering the password/OTP/MFA stage,cost={_cost(step_started)}")
    step_started = time.monotonic()
    session_info = _login_via_password_or_otp(
        session,
        email,
        otp_after_ts,
        email_source=email_source or None,
    )
    access_token = str((session_info or {}).get("accessToken") or "").strip()
    if not access_token:
        raise RuntimeError("After the email change the original-session liveness check did not get access_token")
    _append_log(account_id, f"Original-session liveness check: login verification and session fetch succeeded,cost={_cost(step_started)}")
    result = {
        "ok": True,
        "status": "live",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "access_token": access_token,
        "session": session_info,
        "proxy_used": session.proxy or None,
        "fingerprint": _safe_fingerprint_for_account(session),
        "fingerprint_text": _safe_fingerprint_text_for_account(session),
    }
    result = complete_authenticated_live_check(account_id=account_id, expected_account=expected_account,
                                               result=result, session=session)
    if not result.get("ok"):
        raise RuntimeError(result.get("error") or "Failed to write the original-session liveness check result")
    _append_log(account_id, f"Original-session liveness check succeeded: the latest AT was written back and the plan was checked automatically,total={_cost(live_started)}")
    return result


def _run(account_id: int, source: str) -> dict:
    new_email = ""
    task_started = time.monotonic()
    stage = "Initialization"
    with _LOCK:
        _RUNNING.add(account_id)
    try:
        _append_log(account_id, f"Task execution started:account_id={account_id} source={source}")
        stage = "reading account"
        account = db.get_account(account_id)
        if not account:
            raise RuntimeError("Account does not exist")
        token = str(account.get("access_token") or "").strip()
        if not token:
            raise RuntimeError("The account has no access_token, please refresh it with a liveness check first AT")
        stage = "claiming new email"
        acquire_started = time.monotonic()
        new_email = acquire_email_from_source(source)
        _append_log(account_id, f"New email claimed successfully:source={source} email={new_email} cost={_cost(acquire_started)}")
        if new_email.lower() == str(account.get("email") or "").lower():
            raise RuntimeError("The claimed email is the same as the current email")
        if not db.mark_account_email_change_running(account_id, new_email):
            raise RuntimeError("The email change task state is no longer valid")

        stage = "creating network session"
        saved_proxy = _proxy(account.get("proxy_used"))
        # When the account has no reusable real proxy URL, route through the global proxy pool first instead of connecting bare.
        current_email = str(account.get("email") or "").strip()
        current_source = str(account.get("email_source") or "").strip().lower()
        session = _new_session(account_id, saved_proxy or None, email=current_email)
        _append_log(
            account_id,
            f"Network session created:route={'account proxy' if saved_proxy else 'global proxy pool / default network'} "
            f"proxy={_proxy_label(getattr(session, 'proxy', None))}",
        )
        _append_log(account_id, f"Fingerprint summary:{session.fingerprint_summary_text()}")

        logger.info("[Email Change] begin account_id=%s old=%s new=%s source=%s", account_id, account.get("email"), new_email, source)
        _append_log(account_id, f"Starting email change: original email={account.get('email') or '-'}, new email={new_email}, source={source}")
        stage = "Send the new email verification code / re-authenticate on demand"
        session, token, after_ts, reauthenticated = _begin_change_with_optional_reauth(
            session,
            account_id=account_id,
            current_email=current_email,
            current_source=current_source,
            new_email=new_email,
            access_token=token,
        )
        _append_log(
            account_id,
            f"New email verification code sent successfully, starting to wait for the OTP;reauth={'yes' if reauthenticated else 'no'}",
        )
        stage = "waiting for new email OTP"
        otp_started = time.monotonic()
        otp = wait_for_otp(new_email, after_ts=after_ts, email_source=source, force_service=True)
        _append_log(account_id, f"New email OTP obtained: source={source} cost={_cost(otp_started)} (the verification code is not written to the log)")
        stage = "verifying new email OTP"
        _, session = _post_with_network_retry(
            session, account_id=account_id,
            path="/backend-api/accounts/change_email/verify", token=token,
            payload={"email": new_email, "code": otp},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "New email OTP verified by the server, starting to update the local account record")

        stage = "updating local account"
        db_started = time.monotonic()
        db.finish_account_email_change(
            account_id, ok=True, new_email=new_email, source=source,
            material_line=email_material_line(new_email, source),
        )
        _append_log(account_id, f"Local account updated successfully: current_email={new_email}, the old AT was cleared,cost={_cost(db_started)}")
        # Packet captures show that the old AT returns 401 right after verify, but the __cf_bm in the current session,OAuth
        # Cookie and the exit continuity are still valid. Prefer logging in again inside this session, to avoid creating another session
        # `/api/auth/csrf` and getting a CF 403; if the original session fails, fall back to the background liveness queue.
        stage = "automatic liveness check after email change"
        try:
            live_result = _check_live_in_current_session(
                session,
                account_id=account_id,
                email=new_email,
                email_source=source,
            )
            live_mode = "same_session"
        except Exception as live_exc:
            _append_log(
                account_id,
                f"Original-session liveness check failed: {type(live_exc).__name__}: {str(live_exc)[:300]}; switching to the background liveness queue",
            )
            logger.warning("[email change] Original-session liveness check failed account_id=%s: %s", account_id, str(live_exc)[:300])
            live_result = _enqueue_live_check_after_change(account_id, new_email)
            live_mode = "queued"
        logger.info("[email change] Success account_id=%s new=%s; liveness check after the email change was executed", account_id, new_email)
        _append_log(account_id, f"Email change task completed:live_check_mode={live_mode} total={_cost(task_started)}")
        return {
            "ok": True, "id": account_id, "email": new_email,
            "live_check_started": bool(live_result.get("ok") or live_result.get("accepted")),
            "live_check_mode": live_mode,
            "live_check_error": None if (live_result.get("ok") or live_result.get("accepted")) else live_result.get("error"),
        }
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        db.finish_account_email_change(account_id, ok=False, new_email=new_email or None, source=source, error=error)
        _append_log(account_id, f"Email change failed:stage={stage} total={_cost(task_started)} error={error}")
        if new_email:
            try:
                release_email_if_unconsumed(new_email, note=f"Account #{account_id} email change failed: {error[:300]}")
                _append_log(account_id, f"Failed-email handling completed: reclaim requested email={new_email}")
            except Exception:
                _append_log(account_id, f"Failed-email reclaim error:email={new_email}")
                logger.exception("[email change] Failed to reclaim the new email: %s", new_email)
        logger.exception("[email change] Failed account_id=%s", account_id)
        return {"ok": False, "id": account_id, "error": error}
    finally:
        with _LOCK:
            _RUNNING.discard(account_id)
        _SLOTS.release()


def enqueue(account_id: int, source: str, trigger: str = "manual") -> dict:
    account_id = int(account_id)
    source = str(source or "").strip().lower()
    if not _SLOTS.acquire(blocking=False):
        return {"accepted": False, "error": "Email change queue is full"}
    if not db.claim_account_email_change(account_id, source, trigger):
        _SLOTS.release()
        return {"accepted": False, "busy": True, "error": "Account is being changed or does not exist"}
    _append_log(account_id, f"Email change task queued:source={source} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(_run, account_id, source)
        return {"accepted": True, "future": future}
    except Exception as exc:
        _SLOTS.release()
        db.finish_account_email_change(account_id, ok=False, error=str(exc))
        _append_log(account_id, f"Email change task submit failed:{type(exc).__name__}: {exc}")
        return {"accepted": False, "error": str(exc)}


def is_running(account_id: int) -> bool:
    with _LOCK:
        return int(account_id) in _RUNNING
