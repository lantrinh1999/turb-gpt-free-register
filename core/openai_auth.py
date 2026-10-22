# -*- coding: utf-8 -*-
"""
OpenAI Auth module
Handles registration requests under the auth.openai.com domain (steps 4-5, 7-8, 10, 12)
and sentinel token requests to sentinel.openai.com (steps 6, 9, 11)
"""
import json
import logging
import random
import secrets
import time

from config import openai_protocol as _protocol_cfg
from core.session import BrowserSession
from core.sentinel import (
    generate_requirements_token,
    build_sentinel_request_body,
)
from core.sentinel_runner import generate_sentinel_token

logger = logging.getLogger(__name__)


def _rotate_document_navigation_id(session: BrowserSession) -> None:
    rotate = getattr(session, "rotate_document_navigation_id", None)
    if callable(rotate):
        rotate()


class EmailOtpInvalidError(RuntimeError):
    """The email verification code is invalid/expired; it can be resent and retried."""


class AccountUnusableError(Exception):
    """
    The OpenAI account for this email is dead (deleted/deactivated/banned); trying again gives the same result.

    Distinguished from ordinary network/risk-control errors: this kind of error means the email material itself is unusable,
    and the upper layer should mark the email failed and drop it directly, instead of putting it back to available for repeated retries.

    Carries error_code for logs and troubleshooting (e.g. account_deactivated).
    """

    def __init__(self, message: str, error_code: str = ""):
        super().__init__(message)
        self.error_code = error_code


# When the remote returns these error codes, the email material is judged dead and is not retried.
_ACCOUNT_DEAD_CODES = frozenset({
    "account_deactivated",   # account deleted/deactivated
    "account_deleted",
    "account_banned",
})

_ACCOUNT_DEAD_TEXT_MARKERS = (
    "account_deactivated",
    "account_deleted",
    "account_banned",
    "account deactivated",
    "account deleted",
    "account banned",
    "account has been deactivated",
    "account has been deleted",
    "account was deactivated",
    "account was deleted",
    "your account has been deactivated",
    "your account has been deleted",
    "your account was deactivated",
    "your account was deleted",
    "账号已停用",
    "账号已禁用",
    "账号已删除",
    "账户已停用",
    "账户已禁用",
    "账户已删除",
)


def detect_account_unusable_text(text: str) -> str:
    """Recognize a dead account from browser page/exception text and return the normalized error_code; returns an empty string when nothing matches."""
    low = str(text or "").lower()
    for code in _ACCOUNT_DEAD_CODES:
        if code in low:
            return code
    if any(marker in low for marker in _ACCOUNT_DEAD_TEXT_MARKERS):
        if "delete" in low or "删除" in low:
            return "account_deleted"
        if "ban" in low or "封" in low:
            return "account_banned"
        return "account_deactivated"
    return ""


def detect_account_unusable_response_body(body: str) -> str:
    """
    Using the same logic as the pure protocol mode, recognize a dead account from error.code of the API response JSON.

    This is not page text recognition; used for the browser/fingerprint browser intercepting
    /api/accounts/email-otp/validate the response and then reading the structured error code from the response body.
    """
    try:
        payload = json.loads(body or "")
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else None
    code = ""
    if isinstance(err, dict):
        code = str(err.get("code") or "")
    elif isinstance(payload, dict):
        code = str(payload.get("code") or payload.get("error_code") or "")
    return code if code in _ACCOUNT_DEAD_CODES else ""


def _extract_error_code(resp) -> str:
    """Extract error.code from the response body JSON (returns an empty string if it cannot be obtained)."""
    try:
        payload = resp.json()
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, dict):
        return str(err.get("code") or "")
    return ""


def _proxy_retry_config() -> tuple[int, float]:
    """Read the hot-reloadable proxy network retry config and constrain abnormal config values."""
    attempts = max(1, int(getattr(_protocol_cfg, "OPENAI_PROXY_RETRY_MAX_ATTEMPTS", 3)))
    delay = max(0.0, float(getattr(_protocol_cfg, "OPENAI_PROXY_RETRY_DELAY", 1.0)))
    return attempts, delay


def _is_transient_network_error(exc: Exception) -> bool:
    """Recognize retryable temporary network errors (TLS / connection timeout / connection reset / proxy refusal)."""
    name = type(exc).__name__
    msg = str(exc).lower()
    transient_classes = ("SSLError", "ConnectionError", "Timeout", "CurlError", "ProxyError")
    if any(t.lower() in name.lower() for t in transient_classes):
        return True
    transient_keywords = (
        "wrong_version_number",      # the proxy returned a non-TLS response
        "tls connect",
        "ssl",
        "connection reset",
        "connection refused",
        "timed out",
        "proxy",
        "curl: (97)",                # SOCKS5 failed to connect to the target host
        "curl: (35)",
        "curl: (52)",                # empty reply from server
        "curl: (56)",                # network recv failure
    )
    return any(k in msg for k in transient_keywords)


def _is_retryable_authorize_error(exc: Exception) -> bool:
    """authorize A 403/429/5xx of the navigation can be retried within the same session reusing the new CF Cookie."""
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    if status in (403, 408, 425, 429) or status >= 500:
        return True
    text = str(exc or "").lower()
    return _is_transient_network_error(exc) or any(
        marker in text for marker in (
            "http 403", "http error 403", "status=403",
            "http 429", "http error 429", "status=429", "circuit breaker cooldown",
        )
    )


def _exception_http_status(exc: Exception) -> int:
    """Read the HTTP status code from curl/requests-style exceptions as far as possible."""
    try:
        return int(getattr(getattr(exc, "response", None), "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _reset_retryable_circuit(session: BrowserSession) -> None:
    """Only clear the local circuit breaker, keeping the Cookie Jar and the complete identity context of the current Session."""
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    else:
        session.blocked_until = 0.0
        session.blocked_reason = ""


def _check_stop_requested() -> None:
    """Lazily load the task service, to avoid a circular dependency between main/registration_service at module import time."""
    from core.registration_service import check_stop_requested
    check_stop_requested()


def _interruptible_sleep(seconds: float, interval: float = 0.25) -> None:
    """Wait in segments, so a manual stop in the WebUI does not need to wait for the full exponential backoff to end."""
    deadline = time.monotonic() + max(0.0, float(seconds))
    while True:
        _check_stop_requested()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(max(0.01, interval), remaining))


def _request_with_proxy_retry(session: BrowserSession, label: str, fn):
    """Limited exponential-backoff retries for proxy/TLS/timeout and recoverable HTTP errors."""
    max_attempts, retry_delay = _proxy_retry_config()
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        _check_stop_requested()
        try:
            response = fn()
            response.raise_for_status()
            if attempt > 1:
                logger.info("[%s] proxy link retry succeeded (%s/%s)", label, attempt, max_attempts)
            return response
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_authorize_error(exc) or attempt >= max_attempts:
                raise
            _reset_retryable_circuit(session)
            backoff = retry_delay * (2 ** (attempt - 1))
            logger.warning(
                "[%s] Proxy link failed temporarily (%s/%s): %s: %s, keeping the current session, retrying in %.1fs",
                label, attempt, max_attempts, type(exc).__name__, str(exc)[:180], backoff,
            )
            _interruptible_sleep(backoff)
    raise last_exc if last_exc else RuntimeError(f"{label} Retries exhausted without an exception record")


def network_preflight(session: BrowserSession) -> None:
    """
    Network pre-check before registration: only establishes the edge node / cookie / basic connectivity, carrying no email and triggering no OTP.

    This way, before the authorize redirect that would really "burn an email" happens, it is already confirmed that the current proxy,TLS
    impersonate and the ChatGPT/Auth/Sentinel links are all reachable.
    """
    # In a successful Roxy chain only the ChatGPT login page is visited before OAuth authorize; hitting directly in advance
    # auth/log-in and the Sentinel frame would create a cross-site access sequence that does not exist in a browser.
    timeout = max(1.0, float(getattr(_protocol_cfg, "OPENAI_PREFLIGHT_TIMEOUT", 12.0)))
    checks = [
        ("chatgpt-auth-login", lambda: session.get(
            "https://chatgpt.com/auth/login",
            # Successful browser samples are address-bar-level top-level navigations: no Referer,
            # Sec-Fetch-Site=none. Forging a same-origin Referer / cache-refresh headers triggers a CF challenge.
            headers=session.get_chatgpt_navigate_headers(referer=""),
            allow_redirects=True,
            timeout=timeout,
        )),
    ]
    for label, fn in checks:
        resp = _request_with_proxy_retry(session, f"pre-check:{label}", fn)
        observe = getattr(session, "observe_chatgpt_document", None)
        if callable(observe):
            observe(resp)


def follow_authorize(session: BrowserSession, authorize_url: str) -> str:
    """
    Step 4: follow the authorize URL redirects.
    GET auth.openai.com/api/accounts/authorize?...

    This request produces a series of redirects and establishes the session cookies of auth.openai.com.
    Temporary network errors (proxy hiccups / TLS handshake failures etc.) are retried automatically.

    Args:
        session: browser session
        authorize_url: obtained in step 3 authorize URL
    """
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")

    max_attempts, retry_delay = _proxy_retry_config()
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"[Step 4] Following the authorize URL redirects (attempt {attempt}/{max_attempts})...")
            resp = session.get(authorize_url, headers=headers, allow_redirects=True)
            resp.raise_for_status()
            final_url = str(getattr(resp, "url", "") or "")
            _rotate_document_navigation_id(session)
            logger.info(f"[Step 4] Redirects finished, final URL: {final_url}")
            return final_url
        except Exception as exc:
            last_exc = exc
            if _exception_http_status(exc) == 403:
                if attempt >= max_attempts:
                    logger.warning("[Step 4] authorize HTTP 403, the maximum number of retries has been reached")
                    raise
                _reset_retryable_circuit(session)
                backoff = retry_delay * (2 ** (attempt - 1))
                logger.warning(
                    "[Step 4] authorize HTTP 403, keeping the current fingerprint and Cookie, retrying in %.1fs (%s/%s)",
                    backoff, attempt, max_attempts,
                )
                time.sleep(backoff)
                continue
            if not _is_retryable_authorize_error(exc):
                # Non-temporary errors (such as 4xx business errors) are raised directly without retrying
                raise
            if attempt >= max_attempts:
                break
            # The first 403 often refreshes __cf_bm at the same time; keep the same BrowserSession/Cookie
            # Jar, only clear the local circuit breaker and retry; the session must not be rebuilt and lose this Cookie.
            _reset_retryable_circuit(session)
            backoff = retry_delay * (2 ** (attempt - 1))
            logger.warning(
                f"[Step 4] authorize failed temporarily ({type(exc).__name__}: {str(exc)[:120]}),"
                f"keeping the current session/deviceId/CF Cookie, retrying in {backoff:.1f}s..."
            )
            time.sleep(backoff)

    # All three attempts failed: raise the last exception
    raise last_exc if last_exc else RuntimeError("Step 4 retries exhausted without an exception record")


def request_sentinel_token(session: BrowserSession, flow: str) -> dict:
    """
    Steps 6/9/11: request the Sentinel Token.
    POST https://sentinel.openai.com/backend-api/sentinel/req

    Args:
        session: browser session
        flow: flow type
            - "username_password_create": Step 6
            - "email_otp_validate": Step 9
            - "oauth_create_account": Step 11

    Returns:
        sentinel Response JSON, containing token, turnstile, proofofwork etc.
    """
    iframe_flow = flow == "username_password_create"
    context_name = "password" if iframe_flow else "top_level"
    ready_contexts = getattr(session, "_sentinel_frame_contexts", None)
    if not isinstance(ready_contexts, set):
        ready_contexts = set()
        setattr(session, "_sentinel_frame_contexts", ready_contexts)
    if context_name not in ready_contexts:
        # In a successful browser the same Sentinel iframe is loaded before the first req of both SDK instances.
        # Executed on demand after authorize, to avoid creating a cross-site access sequence that does not exist in the pre-check phase.
        from config import SENTINEL_SV
        frame_url = f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SV}"
        frame_headers = session.get_sentinel_frame_headers(user_initiated=iframe_flow)
        frame_resp = _request_with_proxy_retry(
            session,
            f"Sentinel iframe:{flow}",
            lambda: session.get(frame_url, headers=frame_headers, allow_redirects=True),
        )
        ready_contexts.add(context_name)

    url = "https://sentinel.openai.com/backend-api/sentinel/req"

    # Generate the p field (browser fingerprint)
    sentinel_sid = getattr(
        session,
        "sentinel_iframe_sid" if iframe_flow else "sentinel_sid",
        session.device_id,
    )
    profile = dict(getattr(session, "browser_profile", None) or {})
    profile["build_id"] = None
    # frame.html itself lives under /backend-api/, but the real SDK picks the versioned
    # /sentinel/<sv>/sdk.js when generating p[5]. The password iframe is the same as the later top-level context.
    profile["script_src_samples"] = [
        f"https://sentinel.openai.com/sentinel/{__import__('config', fromlist=['SENTINEL_SV']).SENTINEL_SV}/sdk.js"
    ]
    context_p = getattr(session, "_sentinel_context_p", None)
    if not isinstance(context_p, dict):
        context_p = {}
        setattr(session, "_sentinel_context_p", context_p)
    p = context_p.get(context_name)
    if not p:
        p = generate_requirements_token(sentinel_sid, profile=profile)
        context_p[context_name] = p

    # Build the request body
    body = build_sentinel_request_body(p, session.device_id, flow)

    headers = session.get_sentinel_headers()

    logger.info(f"[Sentinel] Requesting sentinel token, flow={flow}")
    resp = _request_with_proxy_retry(
        session,
        f"Sentinel token:{flow}",
        lambda: session.post(url, headers=headers, data=body),
    )

    data = resp.json()
    if isinstance(data, dict):
        # turnstile.dx bound to this requirements p. The Node runner must hand the same p
        # back to the SDK as cachedProof, and must not use another proof re-sampled inside the VM.
        data = dict(data)
        data["_request_p"] = p
    logger.info(f"[Sentinel] Got the sentinel token successfully, persona={data.get('persona')}")

    if data.get("proofofwork", {}).get("required"):
        seed = data["proofofwork"]["seed"]
        difficulty = data["proofofwork"]["difficulty"]
        logger.info(f"[Sentinel] Needs PoW: seed={seed}, difficulty={difficulty}")

    # Enhanced diagnostics: which anti-bot mechanisms were required
    requires = []
    if data.get("turnstile", {}).get("required"):
        requires.append("turnstile")
    if data.get("so", {}).get("required"):
        requires.append("so")
    if data.get("proofofwork", {}).get("required"):
        requires.append("pow")
    logger.info(f"[Sentinel] Server requirements: {requires or 'none'}")

    return data


def request_password_sentinel_bundle(session: BrowserSession) -> dict:
    """Reproduce the Sentinel flow bundle at the first load of the password page iframe.

    The current Web page uses the same iframe SDK instance, the same ``p`` and the same SID in turn to
    probe ``email_otp_validate``, ``username_password_create``,
    ``authorize_continue``. When really submitting user/register only the password flow
    challenge is consumed; the other two responses are only used to let the server see a capability initialization consistent with the page.
    """
    context_name = "password"
    ready_contexts = getattr(session, "_sentinel_frame_contexts", None)
    if not isinstance(ready_contexts, set):
        ready_contexts = set()
        setattr(session, "_sentinel_frame_contexts", ready_contexts)
    if context_name not in ready_contexts:
        from config import SENTINEL_SV
        frame_url = f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SV}"
        _request_with_proxy_retry(
            session,
            "Sentinel iframe:password bundle",
            lambda: session.get(
                frame_url,
                headers=session.get_sentinel_frame_headers(user_initiated=True),
                allow_redirects=True,
            ),
        )
        ready_contexts.add(context_name)

    profile = dict(getattr(session, "browser_profile", None) or {})
    profile["build_id"] = None
    from config import SENTINEL_SV
    profile["script_src_samples"] = [
        f"https://sentinel.openai.com/sentinel/{SENTINEL_SV}/sdk.js"
    ]
    sid = getattr(session, "sentinel_iframe_sid", session.device_id)
    # The three reqs of the browser sample carry exactly the same p, instead of re-randomizing it for each flow.
    p = generate_requirements_token(sid, profile=profile)
    context_p = getattr(session, "_sentinel_context_p", None)
    if not isinstance(context_p, dict):
        context_p = {}
        setattr(session, "_sentinel_context_p", context_p)
    context_p[context_name] = p
    responses: dict[str, dict] = {}
    for flow in (
        "email_otp_validate",
        "username_password_create",
        "authorize_continue",
    ):
        body = build_sentinel_request_body(p, session.device_id, flow)
        resp = _request_with_proxy_retry(
            session,
            f"Sentinel password bundle:{flow}",
            lambda body=body: session.post(
                "https://sentinel.openai.com/backend-api/sentinel/req",
                headers=session.get_sentinel_headers(),
                data=body,
            ),
        )
        response_data = resp.json()
        if isinstance(response_data, dict):
            response_data = dict(response_data)
            response_data["_request_p"] = p
        responses[flow] = response_data
    logger.info("[Sentinel] Password page flow bundle initialization completed")
    return responses["username_password_create"]


def build_sentinel_header(session: BrowserSession, sentinel_resp: dict, flow: str) -> tuple:
    """
    Build the openai-sentinel-token and openai-sentinel-so-token request header values from the sentinel response.

    Strategy: feed the challenge to sentinel-runner.js (Node + sdk.js executed in a vm sandbox),
    let the real SDK produce the final token containing turnstile / so / pow itself, avoiding hard-stuffing dx that risk control rejects.

    Args:
        session: Browser session (provides device_id and user_agent, which must stay consistent with the later HTTP requests)
        sentinel_resp: sentinel/req response JSON
        flow: Flow type, must be exactly the same flow as passed when requesting the challenge

    Returns:
        (sentinel_header, so_header) tuple
        sentinel_header: openai-sentinel-token Request header value (the JSON string produced directly by the runner)
        so_header: openai-sentinel-so-token Request header value (filled if the SDK output contains an so field, otherwise None)
    """
    from config import USER_AGENT

    iframe_flow = flow == "username_password_create"
    sentinel_sid = getattr(
        session,
        "sentinel_iframe_sid" if iframe_flow else "sentinel_sid",
        None,
    )
    header_value = generate_sentinel_token(
        challenge=sentinel_resp,
        flow=flow,
        device_id=session.device_id,
        user_agent=(getattr(session, "browser_profile", {}) or {}).get("user_agent") or USER_AGENT,
        browser_profile=getattr(session, "browser_profile", None),
        sentinel_sid=sentinel_sid,
        react_listening_key=getattr(session, "react_listening_key", None),
        react_container_key=getattr(session, "react_container_key", None),
        react_resources_key=getattr(session, "react_resources_key", None),
        cookie=session.auth_cookie_header() if hasattr(session, "auth_cookie_header") else f"oai-did={session.device_id}",
    )

    # Parse the runner output and extract the so field separately to fill openai-sentinel-so-token
    so_header = None
    try:
        parsed = json.loads(header_value)
        # runner _so is only for inter-process passing and must not be mixed into the main sentinel-token request header.
        so_value = parsed.pop("_so", None) or parsed.pop("so", None)
        header_value = json.dumps(parsed, separators=(',', ':'))
        if so_value:
            so_header = json.dumps(
                {
                    "so": so_value,
                    "c": parsed.get("c", sentinel_resp.get("token", "")),
                    "id": session.device_id,
                    "flow": flow,
                },
                separators=(',', ':'),
            )
            logger.info(f"[Sentinel] SO field detected, so-token header built")
    except (ValueError, TypeError) as exc:
        logger.warning(f"[Sentinel] runner output parsing failed: {exc}")

    return header_value, so_header


def generate_registration_password(length: int = 14) -> str:
    """Generate a strong password consistent with the Roxy registration; REGISTER_PASSWORD takes priority when configured."""
    try:
        from config import register as register_cfg
        configured = str(getattr(register_cfg, "REGISTER_PASSWORD", "") or "").strip()
        if configured:
            return configured
    except Exception:
        pass
    length = max(8, min(int(length), 64))
    groups = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "abcdefghjkmnpqrstuvwxyz",
        "23456789",
        "!@#$%^&*?_-+=",
    )
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


def navigate_create_account_password(
    session: BrowserSession,
    current_url: str | None = None,
) -> str:
    """Enter the registration password page, ensuring protocol registration no longer takes the passwordless OTP branch."""
    current = str(current_url or "")
    if "/create-account/password" in current:
        return current

    url = "https://auth.openai.com/create-account/password"
    referer = current if current.startswith("https://auth.openai.com/") else "https://auth.openai.com/"
    headers = session.get_auth_navigate_headers(referer=referer)
    headers["sec-fetch-site"] = "same-origin"
    headers["sec-fetch-user"] = "?1"
    logger.info("[Step 5] Switching to the create-account password page...")
    resp = session.get(url, headers=headers, allow_redirects=True)
    resp.raise_for_status()
    _rotate_document_navigation_id(session)
    final_url = str(getattr(resp, "url", "") or url)
    if "/create-account/password" not in final_url:
        raise RuntimeError(f"Cannot enter the registration password page, final landing: {final_url}")
    logger.info("[Step 5] Entered the create-account password page")
    return final_url


def register_user(
    session: BrowserSession,
    email: str,
    password: str,
    sentinel_header: str,
    so_header: str | None = None,
) -> dict:
    """Submit the email and password as in the successful Roxy sample and return the OTP send navigation URL."""
    url = "https://auth.openai.com/api/accounts/user/register"
    headers = session.get_auth_headers(referer="https://auth.openai.com/create-account/password")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    body = json.dumps({"password": password, "username": email}, separators=(",", ":"))
    logger.info("[Step 7] Submitting the email and password:%s", email)
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error("[Step 7] user/register failed status=%s body=%s", resp.status_code, (resp.text or "")[:500])
        resp.raise_for_status()
    data = resp.json()
    return data


def navigate_email_otp_send(session: BrowserSession, continue_url: str | None = None) -> str:
    """Follow the address returned by user/register to send the OTP, and establish the state of the new verification page document."""
    url = str(continue_url or "https://auth.openai.com/api/accounts/email-otp/send")
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/create-account/password")
    headers["sec-fetch-site"] = "same-origin"
    headers["sec-fetch-user"] = "?1"
    resp = session.get(url, headers=headers, allow_redirects=True)
    resp.raise_for_status()
    _rotate_document_navigation_id(session)
    final_url = str(getattr(resp, "url", "") or "")
    if "/email-verification" not in final_url:
        raise RuntimeError(f"OTP abnormal send-navigation landing: {final_url}")
    return final_url

# def get_create_account_page(session: BrowserSession) -> None:
#     """
#     [Backup] Step 5: visit the create-account password page (password branch).
#     GET https://auth.openai.com/create-account/password
#     """
#     url = "https://auth.openai.com/create-account/password"
#     headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
#     headers["sec-fetch-site"] = "same-origin"
#
#     logger.info("[Step 5] Visiting the create-account password page (switching to the password branch)...")
#     resp = session.get(url, headers=headers, allow_redirects=True)
#     resp.raise_for_status()
#     logger.info(f"[Step 5] Create-account password page visited successfully, landing: {resp.url}")


# def register_user(session: BrowserSession, email: str, password: str, sentinel_header: str) -> dict:
#     """
#     [Backup] Step 7: submit the registration request (email + password).
#     POST https://auth.openai.com/api/accounts/user/register
#
#     Returns:
#         Registration response JSON, for example:
#         {
#             "continue_url": "https://auth.openai.com/api/accounts/email-otp/send",
#             "method": "GET",
#             "page": {"type": "email_otp_send", "backstack_behavior": "default"}
#         }
#     """
#     url = "https://auth.openai.com/api/accounts/user/register"
#
#     headers = session.get_auth_headers(referer="https://auth.openai.com/create-account/password")
#     headers["openai-sentinel-token"] = sentinel_header
#
#     body = json.dumps({
#         "password": password,
#         "username": email,
#     })
#
#     logger.info(f"[Step 7] Submitting the registration request, email: {email}")
#     resp = session.post(url, headers=headers, data=body)
#
#     if resp.status_code != 200:
#         logger.error(f"[Step 7] Request failed, status code: {resp.status_code}")
#         logger.error(f"[Step 7] Response content: {resp.text}")
#         resp.raise_for_status()
#
#     data = resp.json()
#     logger.info(f"[Step 7] Registration request succeeded: {data.get('page', {}).get('type')}")
#     return data


# def send_email_otp(session: BrowserSession) -> None:
#     """
#     [Backup] Step 8: trigger sending the email verification code.
#     GET https://auth.openai.com/api/accounts/email-otp/send
#     """
#     url = "https://auth.openai.com/api/accounts/email-otp/send"
#
#     headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/create-account/password")
#     headers["sec-fetch-site"] = "same-origin"
#     headers["sec-fetch-user"] = "?1"
#
#     logger.info("[Step 8] Triggering the email verification code send...")
#     resp = session.get(url, headers=headers, allow_redirects=True)
#     logger.info(f"[Step 8] Verification code send request completed, status code: {resp.status_code}")


def navigate_about_you(session: BrowserSession, about_url: str | None = None) -> str:
    """Enter the about-you page state; when the server returns no continue_url, the default page URL is used as a fallback."""
    url = str(about_url or "https://auth.openai.com/about-you")
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
    headers["sec-fetch-site"] = "same-origin"
    logger.info("[Step 10.5] Navigating to the about-you page to establish the profile page state")
    resp = session.get(url, headers=headers, allow_redirects=True)
    if resp.status_code >= 400:
        raise RuntimeError(f"about-you navigation failed status={resp.status_code}: {(resp.text or '')[:240]}")
    final_url = str(getattr(resp, "url", "") or url)
    if "/api/accounts/user/register" in final_url or "/create-account/password" in final_url:
        raise RuntimeError(f"about-you navigation landed on the old password registration path: {final_url}")
    logger.info(f"[Step 10.5] about-you navigation completed, landing: {final_url}")
    return final_url


def send_email_otp(session: BrowserSession, referer: str = "https://auth.openai.com/email-verification") -> None:
    """Resend the email verification code. Used to fetch a code again after a wrong/expired verification code."""
    url = "https://auth.openai.com/api/accounts/email-otp/send"
    headers = session.get_auth_navigate_headers(referer=referer)
    headers["sec-fetch-site"] = "same-origin"
    headers["sec-fetch-user"] = "?1"
    logger.info("[OTP] Requesting to resend the email verification code...")
    resp = session.get(url, headers=headers, allow_redirects=True)
    if resp.status_code >= 400:
        logger.warning("[OTP] Failed to resend the verification code status=%s: %s", resp.status_code, (resp.text or '')[:300])
        resp.raise_for_status()
    _rotate_document_navigation_id(session)
    logger.info("[OTP] Resend verification code request completed,status=%s", resp.status_code)


def validate_email_otp(session: BrowserSession, code: str, sentinel_header: str | None = None, so_header: str | None = None) -> dict:
    """
    Step 10: submit the email verification code for validation.
    POST https://auth.openai.com/api/accounts/email-otp/validate

    Args:
        session: browser session
        code: 6-digit verification code
        sentinel_header: openai-sentinel-token header value (email_otp_validate flow)

    Returns:
        Validation response JSON, for example:
        {
            "continue_url": "https://auth.openai.com/about-you",
            "method": "GET",
            "page": {"type": "about_you", "backstack_behavior": "default"}
        }
    """
    url = "https://auth.openai.com/api/accounts/email-otp/validate"

    headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")
    if sentinel_header:
        headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
        logger.info("[Step 10] Added the openai-sentinel-so-token header")

    body = json.dumps({"code": code})

    logger.info(f"[Step 10] Submitting the email verification code: {code}")
    resp = session.post(url, headers=headers, data=body)

    if resp.status_code != 200:
        logger.error(f"[Step 10] Request failed, status code: {resp.status_code}")
        logger.error(f"[Step 10] Response content: {resp.text}")
        # First check whether it is a "dead account" - retrying such an email is useless, so raise it separately and let the upper layer mark failed
        err_code = _extract_error_code(resp)
        if err_code in _ACCOUNT_DEAD_CODES:
            raise AccountUnusableError(
                f"Account is dead ({err_code}), the email can no longer be used", error_code=err_code,
            )
        low = (resp.text or '').lower()
        if resp.status_code in (400, 401, 422) and any(k in low for k in (
            'invalid', 'incorrect', 'expired', 'code', 'otp', 'verification',
            'verification code', '認証コード', '確認コード', 'コード'
        )):
            raise EmailOtpInvalidError(f"The email verification code is invalid or has expired: status={resp.status_code}, body={(resp.text or '')[:240]}")
        resp.raise_for_status()

    data = resp.json()
    page_type = data.get('page', {}).get('type')
    logger.info(f"[Step 10] Verification code validated successfully: {page_type}")
    logger.info(f"[Step 10] Validation response summary: {json.dumps(data, ensure_ascii=False)[:1000]}")
    return data


def create_account(session: BrowserSession, name: str, birthday: str, sentinel_header: str, so_header: str = None) -> dict:
    """
    Step 12: submit the user information to complete the registration.
    POST https://auth.openai.com/api/accounts/create_account

    Args:
        session: browser session
        name: user display name
        birthday: birthday, format "YYYY-MM-DD"
        sentinel_header: openai-sentinel-token header value
        so_header: openai-sentinel-so-token header value

    Returns:
        create-account response JSON
    """
    url = "https://auth.openai.com/api/accounts/create_account"

    headers = session.get_auth_headers(referer="https://auth.openai.com/about-you")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
        logger.info(f"[Step 12] Added the openai-sentinel-so-token header")

    body = json.dumps({
        "name": name,
        "birthdate": birthday,
    })

    logger.info(f"[Step 12] Submitting the user information, name: {name}, birthday: {birthday}")
    resp = session.post(url, headers=headers, data=body)

    if resp.status_code != 200:
        logger.error(f"[Step 12] Request failed, status code: {resp.status_code}")
        logger.error(f"[Step 12] Response content: {resp.text}")
        resp.raise_for_status()

    data = resp.json()
    log_cookies = getattr(session, "log_cookie_names", None)
    if callable(log_cookies):
        log_cookies("create_account_complete")
    logger.info("[Step 12] The create endpoint returned success, waiting for the OAuth callback to establish the login state")
    return data
