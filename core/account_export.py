# -*- coding: utf-8 -*-
"""
Post-registration module:
    1. Fetch /api/auth/session and extract the accessToken / user information from it
    2. Set up 2FA (TOTP) and return the secret
    3. Save the account information (email + accessToken + TOTP secret) to SQLite

Reuse the BrowserSession of the registration phase as a whole (same cookie jar / same IP / same UA),
to avoid starting a new session that risk control could link or that lacks the login state.
"""
import json
import logging
import random
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

import pyotp

from core.session import BrowserSession
from core.humanize import delay as human_delay
from core.http_diagnostics import response_summary

logger = logging.getLogger(__name__)


def _clear_twofa_session_circuit(
    session: BrowserSession, *, source: str = "optional warm-up"
) -> None:
    """Clear the circuit-breaker state produced by recoverable 2FA steps.

    The login-state bootstrap calls several non-critical front-end endpoints; a 403 from any one of them will
    trigger the generic circuit breaker of BrowserSession. The warm-up itself may fail, so this breaker must not keep
    blocking the real re-authentication requests that follow (especially ``/api/auth/csrf``).
    """
    blocked_reason = str(getattr(session, "blocked_reason", "") or "")
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    elif getattr(session, "blocked_until", 0.0):
        # Compatible with test stubs or the legacy BrowserSession.
        session.blocked_until = 0.0
        session.blocked_reason = ""
    if blocked_reason:
        logger.info("[2FA] Cleared the circuit-breaker state produced by %s:%s", source, blocked_reason)


_RETRYABLE_REAUTH_HINTS = (
    "403", "408", "425", "429", "500", "502", "503", "504",
    "proxy", "socks", "timeout", "timed out", "connection", "closed",
    "reset", "temporarily unavailable", "circuit breaker cooldown",
)


def _is_retryable_reauth_error(exc: BaseException) -> bool:
    """Only retry rate limits, server errors and transport failures; ordinary business 4xx are not retried."""
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    if status:
        return status in (403, 408, 425, 429) or status >= 500
    text = str(exc or "").lower()
    return any(hint in text for hint in _RETRYABLE_REAUTH_HINTS)


def _trigger_reauth_with_retry(session: BrowserSession, email: str) -> str:
    """Run a limited exponential-backoff retry for temporary failures in the CSRF + signin stage."""
    from config import twofa as _twofa_cfg

    max_attempts = max(1, min(8, int(
        getattr(_twofa_cfg, "TWOFA_REAUTH_MAX_ATTEMPTS", 3) or 3
    )))
    base_delay = max(0.0, min(60.0, float(
        getattr(_twofa_cfg, "TWOFA_REAUTH_RETRY_DELAY", 3.0) or 0.0
    )))
    last_exc: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            auth_url = _trigger_reauth(session, email)
            if attempt > 1:
                logger.info("[2FA] Re-authentication start retry succeeded:attempt=%s/%s", attempt, max_attempts)
            return auth_url
        except Exception as exc:
            last_exc = exc
            retryable = _is_retryable_reauth_error(exc)
            response = getattr(exc, "response", None)
            status = getattr(response, "status_code", None)
            # CSRF/signin explicit rejections are not replayed repeatedly by clearing the local circuit breaker.
            if str(status) == "403" or (status is None and re.search(r"\b403\b", str(exc))):
                retryable = False
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[2FA] Re-authentication start failed and will not be retried:attempt=%s/%s retryable=%s error=%s: %s",
                    attempt, max_attempts, retryable, type(exc).__name__, str(exc)[:200],
                )
                raise

            # 403/429 The BrowserSession circuit breaker has opened; without clearing it the next round would fail locally right away.
            _clear_twofa_session_circuit(session, source="re-authentication request")
            delay = min(120.0, base_delay * (2 ** (attempt - 1)))
            logger.warning(
                "[2FA] Re-authentication start failed temporarily: attempt=%s/%s error=%s: %s; retrying in %.1fs",
                attempt, max_attempts, type(exc).__name__, str(exc)[:200], delay,
            )
            if delay > 0:
                time.sleep(delay)

    assert last_exc is not None
    raise last_exc


def _follow_reauth_with_retry(session: BrowserSession, auth_url: str) -> str:
    """Retry the cross-site authorize navigation; the CF Cookie issued with the first 403 can be reused in the next round."""
    from config import twofa as _twofa_cfg

    max_attempts = max(1, min(8, int(
        getattr(_twofa_cfg, "TWOFA_REAUTH_MAX_ATTEMPTS", 3) or 3
    )))
    base_delay = max(0.0, min(60.0, float(
        getattr(_twofa_cfg, "TWOFA_REAUTH_RETRY_DELAY", 3.0) or 0.0
    )))

    # A newly created protocol session used to hit a complex authorize URL directly from ChatGPT, and the auth domain had no
    # document/locale/CF Cookie context. First do a best-effort warm-up with a simple page; the warm-up
    # and the real authorize still strictly reuse the same BrowserSession/deviceId/Cookie Jar.
    _warm_auth_document_for_reauth(session)

    for attempt in range(1, max_attempts + 1):
        try:
            result = _follow_reauth(session, auth_url)
            if attempt > 1:
                logger.info("[2FA] authorize navigation retry succeeded:attempt=%s/%s", attempt, max_attempts)
            return result
        except Exception as exc:
            retryable = _is_retryable_reauth_error(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[2FA] authorize navigation failed and will not be retried:attempt=%s/%s retryable=%s error=%s: %s",
                    attempt, max_attempts, retryable, type(exc).__name__, str(exc)[:200],
                )
                raise

            # 403 response usually refreshes __cf_bm. Clear the local circuit breaker but keep the Cookie Jar,
            # and the next round keeps using the same OAuth state and navigates with the new Cookie.
            _clear_twofa_session_circuit(session, source="authorize navigation")
            delay = min(120.0, base_delay * (2 ** (attempt - 1)))
            logger.warning(
                "[2FA] authorize navigation failed temporarily: attempt=%s/%s error=%s: %s;"
                "%.1fs retry with the CF Cookie reused afterwards",
                attempt, max_attempts, type(exc).__name__, str(exc)[:200], delay,
            )
            if delay > 0:
                time.sleep(delay)

    raise RuntimeError("authorize navigation retries exhausted")


def _warm_auth_document_for_reauth(session: BrowserSession) -> None:
    """Warm up the top-level auth.openai.com document; on a 403 keep the new Cookie and retry a limited number of times."""
    get_headers = getattr(session, "get_auth_navigate_headers", None)
    request_get = getattr(session, "get", None)
    if not callable(get_headers) or not callable(request_get):
        return
    headers = get_headers(referer="", user_initiated=False)
    for attempt in range(1, 3):
        try:
            resp = request_get(
                "https://auth.openai.com/log-in",
                headers=headers,
                allow_redirects=True,
            )
            status = int(getattr(resp, "status_code", 0) or 0)
            if status < 400:
                logger.info("[2FA] Auth document warm-up completed")
                return
            logger.info("[2FA] Auth document warm-up returned HTTP %s, keeping the response Cookie", status)
        except Exception as exc:
            logger.debug("[2FA] Auth document warm-up error:%s: %s", type(exc).__name__, str(exc)[:160])
        _clear_twofa_session_circuit(session, source="Auth document warm-up")
        if attempt < 2:
            time.sleep(float(attempt))
    logger.info("[2FA] Auth document warm-up did not pass, continuing with the real authorize retry chain")


def _post_register_dwell_seconds(seconds_range: str | None = None) -> float:
    if seconds_range is None:
        try:
            from config import register as _register_cfg

            raw = str(getattr(_register_cfg, "POST_REGISTER_DWELL_SECONDS_RANGE", "5,15") or "0,0").strip()
        except Exception:
            raw = "0,0"
    else:
        raw = str(seconds_range or "0,0").strip()
    try:
        parts = [float(x.strip()) for x in raw.replace(";", ",").replace("|", ",").split(",") if x.strip()]
        if not parts:
            lo = hi = 0.0
        elif len(parts) == 1:
            lo = hi = parts[0]
        else:
            lo, hi = parts[0], parts[1]
    except Exception:
        lo = hi = 0.0
    lo, hi = max(0.0, lo), max(0.0, hi)
    if hi < lo:
        lo, hi = hi, lo
    seconds = random.uniform(lo, hi) if hi > lo else lo
    return max(0.0, min(300.0, seconds))


def post_register_dwell(
    email: str,
    *,
    label: str = "after registration",
    seconds_range: str | None = None,
) -> None:
    """Stay for a random time after a successful registration; reused by the different browser drivers."""
    seconds = _post_register_dwell_seconds(seconds_range)
    if seconds <= 0:
        return
    logger.info("[%s] Staying randomly for %.1fs after successful registration:%s", label, seconds, email)
    time.sleep(seconds)


def _account_material_line(email: str, row: dict | None = None) -> str:
    """Output the original Outlook material first; fall back to the email address when there is none."""
    if row:
        base = row.get("original_email_line") or row.get("email") or email
        password = ""
        if isinstance(row.get("extra_json"), str) and row.get("extra_json"):
            try:
                extra = json.loads(str(row.get("extra_json") or ""))
                password = str(extra.get("registration_password") or "").strip()
            except Exception:
                password = ""
        if not password:
            password = str(row.get("password") or "").strip()
        parts = [p for p in str(base or "").split("----") if p != ""]
        if password:
            if not parts:
                base = password
            elif len(parts) == 1:
                if parts[0] != password:
                    parts.insert(1, password)
                base = "----".join(parts)
            elif parts[1] != password:
                looks_like_material = (
                    parts[1].startswith("M.")
                    or parts[1].startswith("m.")
                    or (len(parts[1]) >= 32 and parts[1].count("-") >= 4)
                    or any(ch in parts[1] for ch in ("@", ":", "/", "\\"))
                )
                if looks_like_material:
                    parts.insert(1, password)
                    base = "----".join(parts)
        return base
    return email


def _account_copy_line(
    material_line: str,
    access_token: str,
    gpt_password: str | None = None,
    totp_secret: str | None = None,
) -> str:
    """Generate a one-line archive entry containing the token, convenient to copy from the batch summary file."""
    parts = [material_line, access_token]
    if gpt_password or totp_secret:
        parts.append(str(gpt_password or ""))
    if totp_secret:
        parts.append(totp_secret)
    return "----".join(parts)


def create_batch_archive_dir(count: int, workers: int = 1) -> None:
    """Kept for legacy callers; batch data is now saved directly to SQLite and no archive directory is created."""
    return None


def _append_batch_archive(
    *,
    row_id: int,
    email: str,
    access_token: str,
    totp_secret: str | None,
    email_source: str | None,
    proxy_used: str | None,
    extra: dict,
    batch_dir: Path | None,
) -> None:
    """Kept for legacy callers; registered accounts are already saved to SQLite by db.insert_account."""
    from core import db
    # The parameter is kept for compatibility with the registration drivers; batch_dir is no longer read and no archive file is written.
    _ = (db, row_id, email, access_token, totp_secret, email_source, proxy_used, extra, batch_dir)
    return None


def follow_oauth_callback(session: BrowserSession, continue_url: str, referer: str = "https://auth.openai.com/about-you") -> str:
    """
    Step 12.5: follow the continue_url returned by create_account to complete the OAuth callback.

    create_account The continue_url returned after success usually points to
        https://auth.openai.com/authorize/continue?...
    It then 302-redirects to
        https://chatgpt.com/api/auth/callback/openai?code=...&state=...
    The callback request makes chatgpt.com set the `__Secure-next-auth.session-token` cookie,
    only after which /api/auth/session can return the accessToken.

    Returns:
        Final landing URL of the redirect chain (usually an address on chatgpt.com)
    """
    if not continue_url:
        raise ValueError("continue_url is empty, cannot complete the OAuth callback")

    # continue_url Usually auth.openai.com/authorize/continue;
    # OTP the external_url branch may also hand out the chatgpt.com callback address directly.
    # Choose the navigation headers by target domain, so the auth step is correct but the request header semantics are not inconsistent.
    if str(continue_url).startswith("https://chatgpt.com"):
        headers = session.get_chatgpt_navigate_headers(referer=referer)
    else:
        headers = session.get_auth_navigate_headers(referer=referer)

    logger.info(f"[OAuth callback] follow continue_url to complete the OAuth callback...")
    resp = session.get(continue_url, headers=headers, allow_redirects=True)
    # A 403/429 of the callback must surface in this stage; otherwise, although the BrowserSession has tripped its breaker,
    # the error would be delayed until fetch_session and the liveness check could not retry the original callback request.
    resp.raise_for_status()
    observe = getattr(session, "observe_chatgpt_document", None)
    if callable(observe):
        observe(resp)
    log_cookies = getattr(session, "log_cookie_names", None)
    if callable(log_cookies):
        log_cookies("oauth_callback_complete")
    logger.info(f"[OAuth callback] completed, final landing point: {resp.url}")
    return resp.url


def fetch_session(session: BrowserSession) -> dict:
    """
    GET https://chatgpt.com/api/auth/session
    Call right after a successful registration to get accessToken / user / account / expires.

    Returns:
        Full session JSON, containing the fields:
            - accessToken: str (Bearer token, used for backend-api calls)
            - user: {id, name, email, idp, iat, mfa}
            - account: {id, planType, structure, ...}
            - expires: ISO time string
    """
    url = "https://chatgpt.com/api/auth/session"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")

    logger.info("[Session] Fetch the ChatGPT session information...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("accessToken"):
        logger.error(f"[Session] response has no accessToken: {data}")
        raise RuntimeError("No accessToken obtained, the login state may not have been established")

    user = data.get("user") or {}
    account = data.get("account") or {}
    logger.info(
        f"[Session] success,user_id={user.get('id')}, email={user.get('email')}, "
        f"plan={account.get('planType')}, mfa={user.get('mfa')}"
    )
    return data


def _trigger_reauth(session: BrowserSession, email: str) -> str:
    """
    Steps 2-3: start password re-authentication and return the OpenAI authorize URL.
    The redirect chain automatically triggers a new OTP email (used for 2FA re-authentication).
    """
    # Fetch a fresh csrf again (the old one may have expired)
    csrf_url = "https://chatgpt.com/api/auth/csrf"
    csrf_resp = session.get(csrf_url, headers=session.get_nextauth_headers(referer="https://chatgpt.com/"))
    if csrf_resp.status_code >= 400:
        logger.warning("[2FA] CSRF request rejected:%s", response_summary(csrf_resp))
    csrf_resp.raise_for_status()
    csrf_token = csrf_resp.json()["csrfToken"]
    logger.info(f"[2FA] re-authentication CSRF: {csrf_token[:20]}...")

    # POST /api/auth/signin/openai with the reauth parameter
    query = {
        "connection": "password",
        "login_hint": email,
        "reauth": "password",
        "max_age": "0",
        "ext-oai-did": session.device_id,
    }
    signin_url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query)

    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    body = urlencode({
        "callbackUrl": "https://chatgpt.com/?action=enable&factor=totp",
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info("[2FA] Starting re-authentication signin/openai...")
    resp = session.post(signin_url, headers=headers, data=body)
    if resp.status_code >= 400:
        logger.warning("[2FA] signin request rejected:%s", response_summary(resp))
    resp.raise_for_status()
    auth_url = resp.json().get("url")
    if not auth_url:
        raise RuntimeError(f"did not get reauth authorize URL: {resp.text}")
    return auth_url


def _follow_reauth(session: BrowserSession, auth_url: str) -> str:
    """
    Step 3: follow the authorize URL to trigger the email OTP.
    auth.openai.com It redirects to the /email-verification page, during which the OTP email is sent.
    """
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")
    logger.info("[2FA] Follow the authorize URL to trigger the OTP send...")
    resp = session.get(auth_url, headers=headers, allow_redirects=True)
    resp.raise_for_status()
    logger.info(f"[2FA] landing point URL: {resp.url}")
    return str(getattr(resp, "url", "") or "")


class TwofaOtpRequestError(RuntimeError):
    """Keep the response for the upper layer to recognize, but never write the response body, OTP or credentials into error logs."""
    def __init__(self, response, *, code: str, challenge: bool, business_error: bool = False):
        self.response = response
        self.status_code = int(response.status_code)
        self.error_code = code
        self.challenge = challenge
        self.business_error = business_error
        headers = {str(k).lower(): str(v) for k, v in (getattr(response, "headers", {}) or {}).items()}
        request_id = headers.get("cf-ray") or headers.get("x-request-id") or ""
        request_id = re.sub(r"[^a-zA-Z0-9_-]", "", request_id)[:80]
        hint = ("The server requires interactive verification, automatic retries have stopped, and the setup can be completed on the official page" if challenge else
                "The server explicitly rejected re-authentication, please check the account or login permissions" if code or business_error else
                "The re-authentication OTP request was rejected without a clear error code")
        super().__init__(f"{hint}(HTTP {self.status_code}, stage=OTP verification" +
                         (f",error_code={code}" if code else "") +
                         (f",request_id={request_id}" if request_id else "") + ")")


def _otp_request_error(response) -> TwofaOtpRequestError:
    try:
        payload = response.json()
    except Exception:
        payload = {}
    error = payload.get("error") if isinstance(payload, dict) else None
    code = (error.get("code") or error.get("type") or "") if isinstance(error, dict) else ""
    if not code and isinstance(payload, dict):
        code = payload.get("code") or payload.get("error_code") or ""
    # Only short error identifiers are allowed, to avoid mixing sensitive content echoed by the server into logs.
    code = str(code)
    code = code if re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", code) else ""
    headers = {str(k).lower(): str(v) for k, v in (getattr(response, "headers", {}) or {}).items()}
    body = str(getattr(response, "text", "") or "")[:8192].lower()
    challenge = (headers.get("cf-mitigated", "").lower() == "challenge" or
                 any(marker in body for marker in ("cf-chl-", "challenge-platform", "captcha")))
    return TwofaOtpRequestError(response, code=code, challenge=challenge, business_error=bool(error))


def _validate_twofa_otp_with_retry(session: BrowserSession, code: str) -> str:
    """Only retry 403/429 without a business rejection; do not resend the email, and do not replay a POST timeout whose result is unknown."""
    from config import twofa as cfg
    attempts = max(1, min(8, int(getattr(cfg, "TWOFA_REAUTH_MAX_ATTEMPTS", 3) or 3)))
    delay = max(0.0, min(60.0, float(getattr(cfg, "TWOFA_REAUTH_RETRY_DELAY", 3.0) or 0.0)))
    for attempt in range(1, attempts + 1):
        try:
            return _validate_reauth_otp(session, code)
        except TwofaOtpRequestError as exc:
            if exc.challenge or exc.error_code or exc.business_error or attempt >= attempts:
                raise
            headers = {str(k).lower(): str(v) for k, v in (getattr(exc.response, "headers", {}) or {}).items()}
            retry_after = headers.get("retry-after", "").strip()
            # Non-numeric (HTTP-date) or long cooldowns are handed back to the user; retrying early would violate the server cooldown.
            if retry_after and (not retry_after.isdigit() or len(retry_after) > 3 or int(retry_after) > 120):
                raise
            wait = max(min(120.0, delay * 2 ** (attempt - 1)), int(retry_after or 0))
            logger.warning("[2FA] OTP Request temporarily rejected with HTTP %s, retrying on the original session in %.1fs (%s/%s), no new code is sent",
                           exc.status_code, wait, attempt, attempts)
            if wait:
                time.sleep(wait)
            _clear_twofa_session_circuit(session, source="OTP temporary rejection")
    raise RuntimeError("2FA OTP retries exhausted")


def _validate_reauth_otp(session: BrowserSession, code: str) -> str:
    """
    Step 4: submit the email OTP verification.
    Returns the continue_url (the callback URL with the code parameter, used to jump back to chatgpt.com).
    """
    url = "https://auth.openai.com/api/accounts/email-otp/validate"
    headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")
    body = json.dumps({"code": code})

    logger.info("[2FA] Submitting the email re-authentication OTP (the code is hidden)")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code in (403, 429):
        raise _otp_request_error(resp)
    resp.raise_for_status()
    data = resp.json()
    continue_url = data.get("continue_url")
    if not continue_url:
        raise RuntimeError(f"OTP verification response is missing continue_url: {data}")
    return continue_url


def _exchange_new_token(session: BrowserSession, continue_url: str) -> str:
    """
    Step 5: follow the continue_url to finish the callback, then fetch /api/auth/session again to get the new accessToken
    (the pwd_auth_time embedded in the token is fresh now, so 2FA enroll will accept it).
    """
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
    logger.info("[2FA] Follow continue_url, refresh session-token cookie...")
    callback = session.get(continue_url, headers=headers, allow_redirects=True)
    callback.raise_for_status()

    # Get the new accessToken
    new_session = fetch_session(session)
    new_token = new_session["accessToken"]
    logger.info("[2FA] Obtained the new one after re-authentication: accessToken")
    return new_token


def _enroll_totp(session: BrowserSession, access_token: str) -> tuple[str, str]:
    """
    Step 6: enroll TOTP and return (secret, session_id)
    """
    url = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = f"Bearer {access_token}"
    headers["oai-device-id"] = session.device_id
    headers["oai-language"] = session.navigator_language()

    body = json.dumps({"factor_type": "totp"})

    logger.info("[2FA] Enrolling TOTP...")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error(f"[2FA] enroll failed {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    data = resp.json()
    secret = data.get("secret")
    session_id = data.get("session_id")
    if not secret or not session_id:
        raise RuntimeError(f"enroll response fields missing: {data}")
    logger.info(f"[2FA] TOTP secret obtained: {secret[:4]}...{secret[-4:]}")
    return secret, session_id


def _activate_totp(
    session: BrowserSession,
    access_token: str,
    secret: str,
    session_id: str,
) -> bool:
    """
    Step 7: generate a 6-digit TOTP code from the secret and activate 2FA.
    """
    url = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = f"Bearer {access_token}"
    headers["oai-device-id"] = session.device_id
    headers["oai-language"] = session.navigator_language()

    totp_code = pyotp.TOTP(secret).now()
    body = json.dumps({
        "code": totp_code,
        "factor_type": "totp",
        "session_id": session_id,
    })

    logger.info("[2FA] Activating TOTP enrollment (the code is hidden)")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error(f"[2FA] activate failed {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"activation returned success=false: {data}")
    return True


def setup_2fa(
    session: BrowserSession,
    email: str,
    otp_code: str | None = None,
    access_token: str | None = None,
) -> str:
    """
    The complete 2FA setup flow.
    It triggers another email verification code:
        - USE_EMAIL_SERVICE=True when, automatically pull from the Outlook account pool
        - otherwise the user must enter it manually

    Args:
        session: session that has completed registration
        email: Account email (used as login_hint)
        otp_code: Email verification code (None means obtain it according to the strategy above)

    Returns:
        TOTP secret(Base32 string), can be used directly with pyotp.TOTP() to generate 6-digit dynamic codes
    """
    # Read through the module attribute to support WebUI hot reload
    from config import email as _email_cfg
    from core.chatgpt_bootstrap import authenticated_bootstrap

    logger.info("=" * 60)
    logger.info("Starting setup of 2FA")
    logger.info("=" * 60)

    if access_token:
        try:
            logger.info("[2FA] Warming up the login state with the existing accessToken...")
            authenticated_bootstrap(session, access_token, strict=False)
            human_delay("navigate")
            logger.info("[2FA] accessToken Optional warm-up finished (does not mean the web login state has been established)")
        except Exception as exc:
            logger.warning("[2FA] accessToken Warm-up failed, continuing with the re-authentication flow:%s: %s", type(exc).__name__, str(exc)[:180])
        finally:
            # authenticated_bootstrap(strict=False) is an optional warm-up. Its non-critical endpoints returning
            # 403 open the session-level circuit breaker; without clearing it, the next CSRF request would not even be sent.
            _clear_twofa_session_circuit(session, source="optional warm-up")

    # Phase 1: re-authentication
    logger.info("[2FA] Phase 1: starting re-authentication")
    reauth_otp_after_ts = time.time()
    auth_url = _trigger_reauth_with_retry(session, email)
    logger.info("[2FA] Re-authentication authorize URL obtained")
    human_delay("api")
    _follow_reauth_with_retry(session, auth_url)
    logger.info("[2FA] Followed the re-authentication authorize URL")
    # After landing on email-verification, the browser login page also explicitly GET
    # /api/accounts/email-otp/send; merely following the authorize URL sometimes only opens the page without really
    # delivering the email, especially in the reauth scenario that reuses an accessToken. To stay consistent with liveness checks / web login,
    # explicitly trigger one send.
    from core.openai_auth import send_email_otp
    send_email_otp(session)
    logger.info("[2FA] Explicitly triggered the email re-authentication OTP send")
    human_delay("navigate")

    if otp_code is None:
        if _email_cfg.USE_EMAIL_SERVICE:
            from core.email_provider import wait_for_otp
            logger.info("[2FA] Automatically waiting for the email re-authentication OTP...")
            try:
                otp_code = wait_for_otp(email, after_ts=reauth_otp_after_ts)
            except Exception as first_wait_exc:
                # The re-authentication page has no reliable resend API; starting another authorize
                # flow makes auth.openai.com send a new OTP again. Only one automatic resend is done,
                # to avoid triggering verification codes endlessly when the mail service misbehaves.
                logger.warning(
                    "[2FA] Timed out waiting for the re-authentication OTP the first time, trying to resend the verification code:%s: %s",
                    type(first_wait_exc).__name__, str(first_wait_exc)[:180],
                )
                reauth_otp_after_ts = time.time()
                resend_auth_url = _trigger_reauth_with_retry(session, email)
                human_delay("api")
                _follow_reauth_with_retry(session, resend_auth_url)
                send_email_otp(session)
                logger.info("[2FA] Re-authentication OTP re-triggered, starting the second round of waiting")
                # Remail receivedAt may be tens of seconds earlier than the local send time (gateway cache / clock
                # skew); in the second round after a resend the lower time bound is relaxed so a code that already arrived is not after_ts
                # filtered out; if an old code is obtained, the 401 retry logic later still validates it.
                broad_after_ts = max(0.0, reauth_otp_after_ts - 120.0)
                logger.info("[2FA] Time-skew tolerance enabled for the second round of code retrieval:after_ts=%.0f", broad_after_ts)
                otp_code = wait_for_otp(email, after_ts=broad_after_ts)
            logger.info("[2FA] Received the email re-authentication OTP")
        else:
            logger.info("")
            logger.info("[2FA] Please check your email and enter the newly received 6-digit verification code")
            otp_code = input(">>> 2FA verification code: ").strip()
            logger.info("[2FA] Manually entered the email re-authentication OTP")

    human_delay("otp_input")
    logger.info("[2FA] Submitting the email re-authentication OTP...")
    try:
        continue_url = _validate_twofa_otp_with_retry(session, otp_code)
    except Exception as first_exc:
        # Some code-retrieval APIs briefly return the previous email from cache. If the server rejects the verification code,
        # poll once more and submit the latest candidate, so an old first code does not terminate the whole 2FA flow right away.
        status_code = getattr(getattr(first_exc, "response", None), "status_code", None)
        if status_code != 401 or not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
            raise
        logger.warning("[2FA] First OTP was rejected, fetching the latest verification code and trying once more")
        from core.email_provider import wait_for_otp
        retry_settle = max(8, int(getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5) or 5))
        fresh_otp = wait_for_otp(
            email,
            after_ts=reauth_otp_after_ts,
            settle_seconds=retry_settle,
        )
        if fresh_otp == otp_code:
            logger.warning("[2FA] The retry still got the same verification code, submitting anyway to keep the original error information")
        else:
            logger.info("[2FA] Got a new verification code, replacing the first candidate")
        otp_code = fresh_otp
        continue_url = _validate_twofa_otp_with_retry(session, otp_code)
    logger.info("[2FA] Email re-authentication OTP verified")
    human_delay("api")
    logger.info("[2FA] Exchanging the new token...")
    new_token = _exchange_new_token(session, continue_url)
    logger.info("[2FA] Got the new token")
    human_delay("api")

    # Phase 2:enroll + activate
    logger.info("[2FA] Phase 2: starting enroll TOTP")
    secret, session_id = _enroll_totp(session, new_token)
    logger.info("[2FA] enroll success,session_id=%s", session_id)
    human_delay("form")
    logger.info("[2FA] Activating TOTP enrollment")
    _activate_totp(session, new_token, secret, session_id)
    logger.info("[2FA] TOTP activation completed")

    logger.info("=" * 60)
    logger.info(f"✅ 2FA setup completed! Secret: {secret[:4]}...{secret[-4:]}")
    logger.info("=" * 60)
    return secret


def save_account_data(
    email: str,
    access_token: str,
    totp_secret: str | None = None,
    extra: dict | None = None,
    output_path: Path | None = None,  # Compatible with the old interface, deprecated
    email_source: str | None = None,
    proxy_used: str | None = None,
    batch_dir: Path | None = None,
    auto_plan_check: bool | None = None,
) -> int:
    """
    Save the account information to SQLite; output_path is only kept for compatibility with legacy callers.
    Returns the row id that was newly inserted/updated.
    """
    from core.db import insert_account
    extra = dict(extra or {})
    # Remail service token only exists in the in-process context. After a successful registration the order context is
    # saved together into the account extra_json, so a liveness check after a service restart can recover it and no longer depends on the "same process
    # having claimed the email first". The normal account list does not return extra_json.
    if str(email_source or "").strip().lower() == "remail":
        try:
            from core.remail_client import get_account_context_metadata

            remail_metadata = get_account_context_metadata(email)
            if remail_metadata:
                existing_service = extra.get("email_service")
                merged_service = dict(existing_service) if isinstance(existing_service, dict) else {}
                merged_service.update(remail_metadata)
                extra["email_service"] = merged_service
        except Exception as exc:
            # A failure to save the order context must not fail a registration that already completed; later liveness checks will still
            # try to recover the credentials by searching Remail orders by email with the API Key.
            logger.warning(
                "[Save] Failed to save the Remail order context, will try to recover by email later:%s: %s",
                type(exc).__name__,
                str(exc)[:180],
            )
    user = extra.get("user") or {}
    account = extra.get("account") or {}
    # Lift the top-level codex status/error out of extra.codex so the WebUI can read the account fields directly
    codex = extra.get("codex") or {}
    codex_status = codex.get("status")  # success / failed / skipped
    codex_error = None
    if codex_status == "failed":
        codex_error = codex.get("message")

    row_id = insert_account(
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        user_id=user.get("id"),
        user_name=user.get("name"),
        plan_type=account.get("planType"),
        expires_at=extra.get("expires"),
        proxy_used=proxy_used,
        email_source=email_source,
        extra=extra,
        codex_status=codex_status,
        codex_error=codex_error,
    )
    batch_folder = _append_batch_archive(
        row_id=row_id,
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        email_source=email_source,
        proxy_used=proxy_used,
        extra=extra,
        batch_dir=batch_dir,
    )
    logger.info("[Save] Account and credentials saved to SQLite, id=%s, email=%s", row_id, email)

    auto_twofa = False
    try:
        from config import twofa as _twofa_cfg

        auto_twofa = bool(getattr(_twofa_cfg, "ENABLE_2FA", False))
    except Exception:
        auto_twofa = False
    if auto_twofa and not str(totp_secret or "").strip():
        try:
            from core.twofa_service import enqueue_account_totp_setup

            queued = enqueue_account_totp_setup(
                account_id=row_id,
                email=email,
                access_token=access_token,
                trigger="registration_auto",
                proxy=proxy_used,
            )
            if queued.get("accepted"):
                logger.info(f"[2FA] Automatic 2FA enabling after registration queued: id={row_id}, email={email}")
            elif queued.get("busy"):
                logger.info(f"[2FA] The account already has a 2FA task, the registration flow does not queue it again: id={row_id}, email={email}")
            else:
                logger.warning(f"[2FA] Failed to queue automatic 2FA enabling after registration (does not affect the registration result): {email}, {queued.get('error')}")
        except Exception as exc:
            logger.warning(
                f"[2FA] Error while queuing automatic 2FA enabling after registration (does not affect the registration result): "
                f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
            )

    if auto_plan_check is None:
        try:
            from config import register as _register_cfg

            auto_plan_check = bool(getattr(_register_cfg, "AUTO_PLAN_CHECK_AFTER_REGISTER", False))
        except Exception:
            auto_plan_check = False
    if not auto_plan_check:
        logger.info(f"[Plan] Automatic plan check after registration skipped: id={row_id}, email={email}")
        return row_id
    # session account.planType in it cannot show Plus trial eligibility. After the account is stored it is only responsible for
    # queuing; a dedicated thread pool queries asynchronously and writes the result back, so registration worker threads are not occupied.
    try:
        from core.plan_check_service import enqueue_account_plan_check

        queued = enqueue_account_plan_check(
            account_id=row_id,
            email=email,
            access_token=access_token,
            trigger="registration_auto",
        )
        if queued.get("accepted"):
            logger.info(f"[Plan] Automatic check after registration queued: id={row_id}, email={email}")
        elif queued.get("busy"):
            logger.info(f"[Plan] The account already has a plan check, the registration flow does not queue it again: id={row_id}, email={email}")
        else:
            logger.warning(f"[Plan] Failed to queue the automatic check after registration (does not affect the registration result): {email}, {queued.get('error')}")
    except Exception as exc:
        logger.warning(
            f"[Plan] Error while queuing the automatic check after registration (does not affect the registration result): "
            f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
        )
    return row_id
