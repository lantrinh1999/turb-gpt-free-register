# -*- coding: utf-8 -*-
"""Registered-account liveness check: reuse the existing AT to warm up first and then go through the reauth OTP; successfully refreshing the AT counts as healthy."""
import logging
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from core import db
from core.session import BrowserSession, close_browser_session
from core.codex_oauth import _account_registration_password, _account_totp_secret, _account_totp_code
from core.humanize import delay as human_delay
from core.chatgpt_auth import get_csrf_token, get_providers, probe_auth_session, signin_openai
from core.openai_auth import (
    follow_authorize,
    send_email_otp,
    validate_email_otp,
    EmailOtpInvalidError,
    AccountUnusableError,
    detect_account_unusable_text,
)
from core.account_export import (
    _follow_reauth_with_retry,
    _trigger_reauth_with_retry,
    _validate_reauth_otp,
    fetch_session,
    follow_oauth_callback,
)
from core.email_provider import wait_for_otp

logger = logging.getLogger(__name__)
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"
_RUNNING: set[str] = set()
_RUNNING_LOCK = threading.Lock()

# A failed liveness network pre-check (403/429/proxy/timeout etc.) is mostly caused by the exit IP being flagged by CF or by proxy-pool jitter,
# and is treated as retryable with a new IP; problems of the account itself (dead account / wrong email etc.) are not retried.
_RETRYABLE_NETWORK_HINTS = (
    "403", "429", "502", "503", "504",
    "proxy", "socks", "timeout", "timed out",
    "connection", "closed", "reset",
)

_SESSION_FINGERPRINT_KEYS = {
    "device_id",
    "sentinel_sid",
    "oai_session_id",
    "auth_session_logging_id",
    "datadog_trace_id",
    "datadog_parent_id",
    "react_listening_key",
    "react_container_key",
    "react_resources_key",
}


def _is_retryable_network_error(exc: BaseException) -> bool:
    if isinstance(exc, AccountUnusableError):
        return False
    text = str(exc or "").lower()
    return any(h in text for h in _RETRYABLE_NETWORK_HINTS)


def _new_fingerprint_pinned_session(
    email: str,
    proxy: str | None,
    fingerprint_state: dict | None = None,
) -> BrowserSession:
    """Create the task with exclusive use of the account session; the full identity and browser profile stay fixed within one route attempt."""
    state = fingerprint_state if fingerprint_state is not None else {}
    saved_profile = state.get("browser_profile")
    identity = str(email).strip().lower()
    # Uses the same lifecycle setting as protocol registration: when "keep protocol fingerprint for the same email" is enabled,
    # the liveness check can rebuild the device/session/hardware profile of the registration phase; when disabled every liveness check
    # generates an independent seed. In either mode all stages/retries within the same task stay fixed.
    fingerprint_seed = str(state.get("fingerprint_seed") or "").strip() or None
    if not state.get("fingerprint_initialized"):
        from config import register as register_cfg
        reuse_by_email = bool(
            getattr(register_cfg, "PROTOCOL_REUSE_FINGERPRINT_BY_EMAIL", False)
        ) and not bool(state.get("force_fresh"))
        # “Re-create each time” must be exactly identical to protocol registration: pass no seed, let BrowserSession
        # it generate a real random UUID4. The old implementation first generated a random seed and then derived a UUID5; although the value is also
        # random, the UUID version bits differ from those at registration time, which is an observable fingerprint difference.
        fingerprint_seed = f"registration:{identity}" if reuse_by_email else None
        state["fingerprint_seed"] = fingerprint_seed or ""
        state["fingerprint_mode"] = (
            "registration_email_stable" if reuse_by_email else "fresh_per_check"
        )
        state["fingerprint_initialized"] = True
    session = BrowserSession(
        proxy=proxy,
        # Generate the region profile from the current exit the first time; reuse it as is if it must be rebuilt within the same route.
        detect_exit_geo=not bool(saved_profile),
        browser_profile=dict(saved_profile) if isinstance(saved_profile, dict) else None,
        fingerprint_seed=fingerprint_seed,
        device_id=state.get("device_id"),
        auth_session_logging_id=state.get("auth_session_logging_id"),
        oai_session_id=state.get("oai_session_id"),
        sentinel_sid=state.get("sentinel_sid"),
    )
    for key in (
        "device_id", "auth_session_logging_id", "oai_session_id", "sentinel_sid",
    ):
        state.setdefault(key, str(getattr(session, key, "") or ""))
    if not saved_profile:
        generated_profile = getattr(session, "browser_profile", None)
        if isinstance(generated_profile, dict):
            state["browser_profile"] = dict(generated_profile)
    return session


def _fingerprint_mode_label(state: dict) -> str:
    mode = str(state.get("fingerprint_mode") or "")
    if mode == "registration_email_stable":
        return "reuse the protocol registration fingerprint for the same email"
    return "re-created on every liveness check"


def _warm_login_fingerprint_context(session: BrowserSession) -> None:
    """Reproduce the login page initialization order of a successful plus pure-protocol registration sample."""
    from core.chatgpt_bootstrap import anonymous_bootstrap

    logger.info(
        "[Liveness] Login chain warm-up: /auth/login top-level navigation → anonymous bootstrap → "
        "providers → session → CSRF → session"
    )
    nav = session.get(
        "https://chatgpt.com/auth/login",
        headers=session.get_chatgpt_navigate_headers(
            # Address-bar-level top-level navigation: no Referer, Sec-Fetch-Site=none.
            referer="", user_initiated=True,
        ),
        allow_redirects=True,
        # A reachable proxy port does not mean its upstream TLS works; avoid bad nodes holding a worker for a long time.
        timeout=12,
    )
    nav.raise_for_status()
    observe = getattr(session, "observe_chatgpt_document", None)
    if callable(observe):
        observe(nav)
    anonymous_bootstrap(session, strict=False)
    # best-effort bootstrap non-critical endpoints must not block the real authentication chain.
    _clear_optional_bootstrap_circuit(session)
    get_providers(session)
    probe_auth_session(session)


def _network_preflight_with_retry(
    email: str,
    proxy: str | None,
    max_attempts: int = 4,
    fingerprint_state: dict | None = None,
) -> tuple[BrowserSession, str]:
    """CSRF → Signin Backup pre-check; on failure keep the same session and retry.

    `/api/auth/providers` is just the NextAuth discovery endpoint; the signin endpoint does not depend on what it returns
    content. In practice this endpoint is very easily blocked by Cloudflare first; if it were a hard gate, the CSRF/authorization chain that would
    otherwise work would never run. So the backup liveness chain no longer treats providers as a
    mandatory step.

    ``proxy`` must be passed through unchanged here: ``None`` means pick a proxy according to the config, an empty string means explicitly
    direct. Previously ``proxy if proxy else None`` wrongly turned the direct fallback into drawing a proxy again.
    """
    session: BrowserSession | None = None
    last_exc: BaseException | None = None
    state = fingerprint_state if fingerprint_state is not None else {}
    # One network pre-check creates only one BrowserSession. The new __cf_bm issued with a 403 response and the
    # OAuth/device context all stay in the same Cookie Jar for the next round.
    session = _new_fingerprint_pinned_session(email, proxy, state)
    logger.info("[Liveness] Fingerprint lifecycle:%s", _fingerprint_mode_label(state))
    for attempt in range(1, max_attempts + 1):
        logger.info(
            "[Liveness] Reusing the unified session: proxy=%s device_id=%s oai_session_id=%s (network pre-check %s/%s)",
            session.proxy or "configured random/direct", session.device_id,
            str(getattr(session, "oai_session_id", "") or "")[:12] + "...",
            attempt, max_attempts,
        )
        logger.info("[Liveness] Fingerprint summary:%s", session.fingerprint_summary_text())
        try:
            _warm_login_fingerprint_context(session)
            csrf = get_csrf_token(session)
            # Successful Web samples confirm the anonymous NextAuth session once more before signin.
            probe_auth_session(session)
            authorize_url = signin_openai(session, csrf, email)
            return session, authorize_url
        except Exception as exc:
            last_exc = exc
            if attempt >= max_attempts or not _is_retryable_network_error(exc):
                try:
                    close_browser_session(session)
                except Exception:
                    pass
                raise
            _clear_optional_bootstrap_circuit(session)
            logger.warning(
                "[Liveness] Network pre-check failed (%s/%s), keeping the current session/deviceId/CF Cookie for the retry:%s",
                attempt, max_attempts, str(exc)[:200],
            )
            time.sleep(2)
    raise RuntimeError(f"Network pre-check failed repeatedly:{last_exc}")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_fingerprint_for_account(session: BrowserSession) -> dict:
    """Only the runtime environment profile is recorded in the account; session/device identifiers are not saved."""
    fp = session.fingerprint_summary()
    return {k: v for k, v in fp.items() if k not in _SESSION_FINGERPRINT_KEYS}


def _safe_fingerprint_text_for_account(session: BrowserSession) -> str:
    fp = _safe_fingerprint_for_account(session)
    parts = [
        f"proxy={BrowserSession._short_value(fp.get('proxy') or 'direct', 36)}",
        f"ua={BrowserSession._short_value(fp.get('user_agent'), 72)}",
        f"lang={fp.get('accept_language')}",
        f"tz={fp.get('timezone_iana')}({fp.get('timezone_offset_minutes')})",
        f"screen={fp.get('screen_width')}x{fp.get('screen_height')}@{fp.get('device_pixel_ratio')}",
        f"cpu={fp.get('hardware_concurrency')}",
        f"mem={fp.get('device_memory')}",
        f"geo={fp.get('geo_country') or '?'}:{fp.get('geo_city') or '?'}",
    ]
    return " ".join(parts)


def _extract_continue_url(result: dict | None) -> str:
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    page = page if isinstance(page, dict) else {}
    return str(
        result.get("continue_url")
        or result.get("external_url")
        or result.get("url")
        or page.get("continue_url")
        or page.get("external_url")
        or page.get("url")
        or ""
    ).strip()


def _extract_factor_id(result: dict | None, continue_url: str) -> str:
    if isinstance(result, dict):
        page = result.get("page") or {}
        page = page if isinstance(page, dict) else {}
        payload = page.get("payload") or {}
        if isinstance(payload, dict):
            factor_id = str(payload.get("factor_id") or "").strip()
            if factor_id:
                return factor_id
        if isinstance(page.get("payload"), dict):
            factor_id = str(page["payload"].get("factor_id") or "").strip()
            if factor_id:
                return factor_id
    if "/mfa-challenge/" in continue_url:
        return continue_url.rstrip("/").rsplit("/", 1)[-1]
    return ""


def _password_verify(session: BrowserSession, password: str) -> dict:
    from core.openai_auth import build_sentinel_header, request_sentinel_token

    sentinel_resp = request_sentinel_token(session, "password_verify")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "password_verify")
    headers = session.get_auth_headers(referer="https://auth.openai.com/log-in/password")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    resp = session.post(
        "https://auth.openai.com/api/accounts/password/verify",
        headers=headers,
        data=json.dumps({"password": password}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _mfa_issue_challenge(session: BrowserSession, factor_id: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/issue_challenge",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "force_fresh_challenge": False}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _mfa_verify(session: BrowserSession, factor_id: str, code: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/verify",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "code": code}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _follow_continue_and_fetch(session: BrowserSession, continue_url: str, *, referer: str) -> dict:
    """Complete callback/session, and on a 403 keep the same-session Cookie and retry within the stage.

    callback Retried separately from the session: once the callback succeeds the OAuth code is not consumed again;
    continue_url is only replayed when the callback itself fails. After the retries are exhausted it is thrown to the upper layer, which
    live_check_service falls back to a complete independent direct session according to the existing strategy.
    """
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            follow_oauth_callback(session, continue_url, referer=referer)
            break
        except Exception as exc:
            if attempt >= max_attempts or not _is_retryable_network_error(exc):
                raise
            _clear_optional_bootstrap_circuit(session)
            delay = float(2 ** (attempt - 1))
            logger.warning(
                "[Liveness] OAuth callback failed temporarily (%s/%s), keeping the current "
                "session/deviceId/CF Cookie, retrying in %.1fs:%s",
                attempt, max_attempts, delay, str(exc)[:200],
            )
            time.sleep(delay)

    for attempt in range(1, max_attempts + 1):
        try:
            return fetch_session(session)
        except Exception as exc:
            if attempt >= max_attempts or not _is_retryable_network_error(exc):
                raise
            _clear_optional_bootstrap_circuit(session)
            delay = float(2 ** (attempt - 1))
            logger.warning(
                "[Liveness] Session/AT fetch failed temporarily (%s/%s), keeping the current "
                "session/deviceId/CF Cookie, retrying in %.1fs:%s",
                attempt, max_attempts, delay, str(exc)[:200],
            )
            time.sleep(delay)
    raise RuntimeError("Liveness Session/AT fetch retries exhausted")


def _stored_access_token(email: str) -> str:
    """Read the AT the local account already has, to warm up the login state first and then take the stable reauth chain."""
    try:
        account = db.get_account_by_email(email)
        return str((account or {}).get("access_token") or "").strip()
    except Exception as exc:
        logger.debug("[Liveness] Failed to read the existing accessToken, switching to the backup login chain:%s: %s", type(exc).__name__, exc)
        return ""


def _clear_optional_bootstrap_circuit(session: BrowserSession) -> None:
    """Clear the local circuit breaker caused by the optional login-state warm-up; it does not affect the real authentication requests that follow.

    authenticated_bootstrap is a best-effort warm-up; a 403 from some legacy endpoint there does not mean
    reauth the chain is unusable; if the generic circuit breaker of BrowserSession kept that state it would directly block the following
    `/api/auth/csrf`, so even the stable 2FA chain could not start.
    """
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
        return
    if getattr(session, "blocked_until", 0.0):
        session.blocked_until = 0.0
        session.blocked_reason = ""


def _warm_authenticated_session(session: BrowserSession, access_token: str) -> None:
    """Reuse the login-state warm-up flow already verified by 2FA. A failed warm-up does not directly mark the account dead."""
    if not access_token:
        return
    from core.chatgpt_bootstrap import authenticated_bootstrap

    try:
        logger.info("[Liveness] Warming up the login state with the existing accessToken...")
        authenticated_bootstrap(session, access_token, strict=False)
        logger.info("[Liveness] accessToken warm-up completed, continuing with reauth OTP")
    except Exception as exc:
        # strict=False already swallows most single-endpoint errors; this only catches initialization exceptions.
        logger.warning("[Liveness] accessToken warm-up failed, continuing with reauth OTP:%s: %s", type(exc).__name__, str(exc)[:180])
    finally:
        _clear_optional_bootstrap_circuit(session)


def _exception_response_text(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    return str(getattr(response, "text", "") or "")


def _exception_status_code(exc: BaseException) -> int | None:
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return None
    return status or None


def _validate_reauth_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 3,
    email_source: str | None = None,
) -> str:
    """Submit the reauth OTP; when the code is wrong, resend and fetch a new code."""
    current_otp: str | None = None
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[Liveness] Waiting for the re-authentication OTP: %s (attempt %s/%s)", email, attempt, max_otp_attempts)
                current_otp = wait_for_otp(
                    email,
                    after_ts=otp_after_ts,
                    email_source=email_source,
                )
            human_delay("otp_input")
            continue_url = _validate_reauth_otp(session, current_otp)
            if not continue_url:
                raise RuntimeError("re-authentication OTP verification response is missing continue_url")
            return str(continue_url)
        except AccountUnusableError:
            raise
        except Exception as exc:
            last_exc = exc
            body = _exception_response_text(exc)
            dead_code = detect_account_unusable_text(body) or detect_account_unusable_text(str(exc))
            if dead_code:
                raise AccountUnusableError(
                    f"Account is dead ({dead_code}), the email can no longer be used",
                    error_code=dead_code,
                ) from exc

            status = _exception_status_code(exc)
            # reauth validate 403 may be a Cloudflare/exit block; do not keep sending OTPs on the same tripped
            # session, leave it to the direct fallback of the upper layer.
            retryable_otp = status in (400, 401, 422)
            if attempt >= max_otp_attempts or not retryable_otp:
                raise
            logger.warning(
                "[Liveness] Re-authentication OTP invalid/expired, fetching again after resending (%s/%s):%s",
                attempt,
                max_otp_attempts,
                str(exc)[:180],
            )
            send_email_otp(session)
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("Re-authentication OTP verification failed")


def _login_via_reauth(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """Re-authenticate through the chain already verified by 2FA and refresh the ChatGPT session."""
    auth_url = _trigger_reauth_with_retry(session, email)
    logger.info("[Liveness] reauth authorize URL obtained")
    human_delay("api")
    final_url = _follow_reauth_with_retry(session, auth_url)
    dead_code = detect_account_unusable_text(final_url)
    if dead_code:
        raise AccountUnusableError(f"Account is dead ({dead_code})", error_code=dead_code)
    human_delay("navigate")
    logger.info("[Liveness] Followed the reauth authorize URL, now waiting for the email OTP")
    continue_url = _validate_reauth_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    logger.info("[Liveness] reauth OTP verified, now exchanging the new token")
    human_delay("api")
    return _follow_continue_and_fetch(
        session,
        continue_url,
        referer="https://auth.openai.com/email-verification",
    )


def _login_via_email_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """Complete the email OTP login, follow the OAuth callback, then fetch the ChatGPT session."""
    validate_result = _validate_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    page = validate_result.get("page") if isinstance(validate_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")
    continue_url = _extract_continue_url(validate_result)
    if not continue_url:
        raise RuntimeError(f"OTP login succeeded but no OAuth continue_url: {validate_result}")
    if "about-you" in str(continue_url) or page_type in {"about_you", "about-you"}:
        raise RuntimeError(f"After login this email landed on the profile page, so it is probably not a fully registered account: page_type={page_type}, continue_url={continue_url}")
    logger.info("[Liveness] Email OTP verification done, now following OAuth callback")
    return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/email-verification")


def _login_via_password_or_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """Prefer password login; if it enters an MFA challenge, finish automatically with TOTP."""
    password = _account_registration_password(email)
    if not password:
        logger.info("[Liveness] No registration password found, continuing with email OTP:%s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    logger.info("[Liveness] The account has a password, preferring password login:%s", email)
    password_result = _password_verify(session, password)
    continue_url = _extract_continue_url(password_result)
    page = password_result.get("page") if isinstance(password_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")

    if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
        factor_id = _extract_factor_id(password_result, continue_url)
        secret = _account_totp_secret(email)
        if not factor_id:
            raise RuntimeError(f"After password login it entered MFA but did not get factor_id: {password_result}")
        if not secret:
            raise RuntimeError(f"After password login it entered MFA, but the account has no totp_secret:{email}")
        logger.info("[Liveness] Entered the MFA challenge, now submitting TOTP:%s factor_id=%s", email, factor_id)
        _mfa_issue_challenge(session, factor_id)
        code = _account_totp_code(email)
        if not code:
            raise RuntimeError(f"Cannot generate the TOTP verification code:{email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        mfa_continue_url = _extract_continue_url(mfa_result) or continue_url
        if not mfa_continue_url:
            raise RuntimeError(f"MFA verification succeeded but no continue_url: {mfa_result}")
        return _follow_continue_and_fetch(
            session,
            mfa_continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )

    if "email-verification" in continue_url or page_type in {"email_verification", "email_otp_send"}:
        logger.info("[Liveness] Password login still led to email OTP, continuing with email verification:%s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    if continue_url:
        logger.info("[Liveness] Password login gave the callback address directly, continuing with the callback:%s", email)
        return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/log-in/password")

    raise RuntimeError(f"password login succeeded but there is no usable continue_url: {password_result}")


def _login_via_full_web_flow(
    email: str,
    proxy: str | None,
    *,
    email_source: str | None,
    fingerprint_state: dict,
) -> tuple[BrowserSession, dict]:
    """Establish a brand new login state following the Web login sequence of the plus pure-protocol registration."""
    session, authorize_url = _network_preflight_with_retry(
        email,
        proxy,
        fingerprint_state=fingerprint_state,
    )
    # After the pre-check returns this function holds the session; the duty to release it passes to the upper layer only on successful return.
    try:
        otp_after_ts = time.time()
        final_url = follow_authorize(session, authorize_url)
        dead_code = detect_account_unusable_text(final_url)
        if dead_code:
            raise AccountUnusableError(
                f"Account is dead ({dead_code})",
                error_code=dead_code,
            )
        session_info = _login_via_password_or_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )
        return session, session_info
    except BaseException:
        try:
            close_browser_session(session)
        except Exception:
            logger.warning("[Liveness] Session cleanup error after login failure", exc_info=True)
        raise


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"live-check-{safe}.log"


def is_checking(email: str) -> bool:
    key = str(email or "").strip().lower()
    with _RUNNING_LOCK:
        return key in _RUNNING


def _validate_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 3,
    email_source: str | None = None,
) -> dict:
    current_otp = None
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[Liveness] Waiting for the login OTP: %s (attempt %s/%s)", email, attempt, max_otp_attempts)
                current_otp = wait_for_otp(
                    email,
                    after_ts=otp_after_ts,
                    email_source=email_source,
                )
            result = validate_email_otp(session, current_otp, sentinel_header=None, so_header=None)
            return result
        except EmailOtpInvalidError as exc:
            last_exc = exc
            if attempt >= max_otp_attempts:
                break
            logger.warning("[Liveness] OTP invalid/expired, fetching again after resending:%s", str(exc)[:180])
            send_email_otp(session)
            # Use "after the resend request completes" as the new baseline, so the old code that just failed is not matched again by the after tolerance window.
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
        except Exception as exc:
            # Network jitter after submitting the OTP (connection dropped / timeout / proxy fluctuation): resend the code on the same session and verify once more.
            if attempt >= max_otp_attempts or not _is_retryable_network_error(exc):
                raise
            last_exc = exc
            logger.warning("[Liveness] OTP verification network jitter, fetching again after resending (%s/%s):%s", attempt, max_otp_attempts, str(exc)[:180])
            try:
                send_email_otp(session)
            except Exception:
                raise
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("OTP verification failed")


def check_account_liveness(
    email: str,
    proxy: str | None = None,
    *,
    clear_log: bool = True,
    email_source: str | None = None,
    fingerprint_state: dict | None = None,
    on_authenticated: Callable[[dict, BrowserSession], dict] | None = None,
) -> dict:
    """
    Log in to the account again and refresh the latest accessToken; query the plan on the original session before closing it.

    Returns:
      {
        ok: bool,
        status: live/deactivated/failed,
        access_token: str?,
        session: dict?,
        checked_at: ISO,
        plan_result: dict?,  # Plan query result in the same session when the liveness check succeeded; a failure does not affect the liveness check ok
        error: str?
      }
    """
    email = str(email or "").strip()
    if not email:
        raise ValueError("email cannot be empty")

    checked_at = _now()
    key = email.lower()
    path = log_path(email)
    path.parent.mkdir(parents=True, exist_ok=True)
    if clear_log:
        path.write_text("", encoding="utf-8")

    fh: logging.FileHandler | None = None
    session: BrowserSession | None = None
    task_fingerprint_state = fingerprint_state if fingerprint_state is not None else {}
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    with _RUNNING_LOCK:
        _RUNNING.add(key)
    try:
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)

        logger.info("[Liveness] Log file:%s", path)
        logger.info("[Liveness] Starting re-login:%s", email)
        existing_access_token = _stored_access_token(email)
        has_totp = bool(_account_totp_secret(email))
        if existing_access_token and not has_totp:
            # 2FA The setup flow is already verified: first warm up the ChatGPT login state with the existing AT, then take
            # reauth → the email OTP -> callback. This chain does not depend on the
            # /api/auth/providers, which is easily blocked by CF. Accounts with TOTP enabled keep the password -> MFA path,
            # to avoid mistaking the MFA challenge for the email OTP page.
            logger.info("[Liveness] Flow: login state warm-up -> CSRF -> Reauth Signin -> Authorize -> email OTP → OAuth callback → Session/AT")
            session = _new_fingerprint_pinned_session(email, proxy, task_fingerprint_state)
            logger.info(
                "[Liveness] Fingerprint lifecycle:%s",
                _fingerprint_mode_label(task_fingerprint_state),
            )
            logger.info(
                "[Liveness] Session created: proxy=%s device_id=%s (reusing the stable 2FA chain)",
                session.proxy or "direct/configured random",
                session.device_id,
            )
            logger.info("[Liveness] Fingerprint summary:%s", session.fingerprint_summary_text())
            _warm_authenticated_session(session, existing_access_token)
            human_delay("navigate")
            try:
                session_info = _login_via_reauth(
                    session,
                    email,
                    time.time(),
                    email_source=email_source,
                )
            except Exception as reauth_exc:
                if not _is_retryable_network_error(reauth_exc):
                    raise
                # reauth/callback the same-session stage retries are exhausted. Continuing to reuse the tripped
                # Cookie Jar one is meaningless; following the plus pure-protocol registration, build a clean session and run
                # /auth/login → providers/session/csrf/session → signin the complete re-login.
                failed_proxy = session.proxy if proxy is None else proxy
                logger.warning(
                    "[Liveness] AT reauth chain failed temporarily, switching to a clean session for a full pure-protocol login:%s",
                    str(reauth_exc)[:240],
                )
                try:
                    close_browser_session(session)
                except Exception:
                    pass
                session, session_info = _login_via_full_web_flow(
                    email,
                    failed_proxy,
                    email_source=email_source,
                    fingerprint_state=task_fingerprint_state,
                )
        else:
            # Compatible with records without a local AT or with TOTP enabled; reproduces, following the successful plus registration sample,
            # the login page document and the complete NextAuth call order.
            logger.info(
                "[Liveness] Flow: login page → Providers/Session/CSRF/Session → Signin → "
                "Authorize → password/email OTP -> MFA (if any) → OAuth callback → Session/AT"
            )
            session, session_info = _login_via_full_web_flow(
                email,
                proxy,
                email_source=email_source,
                fingerprint_state=task_fingerprint_state,
            )
        access_token = str(session_info.get("accessToken") or "")
        if not access_token:
            raise RuntimeError("no accessToken after re-login accessToken")

        user = session_info.get("user") or {}
        account = session_info.get("account") or {}
        logger.info("[Liveness] Healthy:%s user_id=%s plan=%s", email, user.get("id"), account.get("planType"))
        fp = _safe_fingerprint_for_account(session)
        result = {
            "ok": True,
            "status": "live",
            "checked_at": checked_at,
            "access_token": access_token,
            "session": session_info,
            "proxy_used": session.proxy or None,
            "fingerprint": fp,
            "fingerprint_text": _safe_fingerprint_text_for_account(session),
        }
        if on_authenticated is not None:
            return on_authenticated(result, session)
        # It is also queried automatically when the low-level liveness check is called directly; the business queue first stores the new AT through a hook and then occupies the plan task in a unified way.
        try:
            from core.chatgpt_plan import check_account_plan
            from core.plan_check_service import _wait_for_rate_slot
            _wait_for_rate_slot()
            result["plan_result"] = check_account_plan(access_token, session=session)
        except Exception as exc:
            result["plan_result"] = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        return result

    except AccountUnusableError as exc:
        code = getattr(exc, "error_code", "") or detect_account_unusable_text(str(exc)) or "account_deactivated"
        logger.warning("[Liveness] Dead account:%s %s", email, code)
        return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
    except Exception as exc:
        code = detect_account_unusable_text(_exception_response_text(exc)) or detect_account_unusable_text(str(exc))
        if code:
            logger.warning("[Liveness] Dead account:%s %s", email, code)
            return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
        logger.warning("[Liveness] Failed:%s %s: %s", email, type(exc).__name__, str(exc)[:260])
        return {"ok": False, "status": "failed", "checked_at": checked_at, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
    finally:
        try:
            logger.info("[Liveness] Finished:%s", email)
            if session is not None:
                try:
                    close_browser_session(session)
                except Exception:
                    pass
            if fh is not None:
                root_logger.removeHandler(fh)
                try:
                    fh.close()
                except Exception:
                    # A saved liveness/plan result must not be overwritten by an exception when the log file is closed.
                    logger.warning("[Liveness] Failed to close the log file", exc_info=True)
        finally:
            with _RUNNING_LOCK:
                _RUNNING.discard(key)
