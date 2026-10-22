# -*- coding: utf-8 -*-
"""
Codex OAuth authorization module after a successful registration (reworked 2026-06-15: brand new session + SMS code receiving).

The old approach of reusing the logged-in session from registration ran into /choose-an-account and hung (the React SPA could not parse out
the submittable fields). The new approach logs in from scratch with a **brand new clean session**, following the standard OpenAI risk-control path,
phone verification receives its codes automatically from a code-receiving platform; core.sms_provider currently supports GrizzlySMS and the L_API.md
locally defined L number service.

The complete API chain is decided dynamically by the page/type/continue_url returned by Auth:
    - After submitting the email it may go to a password, email OTP or another verification page
    - After the password it may go to MFA/TOTP, email OTP, phone verification or straight to authorization
    - After email OTP/MFA, phone verification is likewise only performed when the server explicitly requires it
    - Finally pick the workspace / follow the redirect to localhost:1455/auth/callback

The logic of exchanging the code for a token / saving to SQLite (exchange_codex_token /
build_codex_storage / save_codex_credential) follows the original flow.
"""
import base64
import hashlib
import json
import logging
import random
import secrets
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse, parse_qs, quote

import pyotp

# Access config through module attributes, which supports WebUI hot reload (config.reload_all()).
# Protocol-level constants (CLIENT_ID/URL/SCOPE/OUTPUT_DIRNAME) never change, but are still read uniformly from _cfg,
# so they take effect immediately after a reload and no second set of imports is needed.
from config import codex as _cfg
from core.session import BrowserSession
from core.humanize import delay as human_delay
from core.openai_auth import (
    _is_transient_network_error,
    _is_retryable_authorize_error,
    _reset_retryable_circuit,
    _extract_error_code,
    detect_account_unusable_response_body,
    detect_account_unusable_text,
    AccountUnusableError,
    request_sentinel_token,
    build_sentinel_header,
)
from core import db
from core import sms_provider
from curl_cffi import requests as curl_requests

logger = logging.getLogger(__name__)

# Maximum number of hops when following a redirect chain, to prevent infinite loops
_MAX_REDIRECTS = 15

# Retry parameters for temporary network-layer errors (proxy jitter / TLS handshake failure / reset), aligned with openai_auth.follow_authorize
_NET_MAX_ATTEMPTS = 3
_NET_BACKOFF_BASE = 2.0

# Auth There is occasionally a short race between the response setting the cookie and the following workspace/select.
_WORKSPACE_COOKIE_WAIT_SECONDS = 4.0
_WORKSPACE_POLL_INTERVAL_SECONDS = 0.2


def _with_net_retry(label: str, fn):
    """
    Retry wrapper for temporary network errors (TLS/proxy/timeout/reset).
    Non-temporary errors (business 4xx etc.) are raised directly. At most _NET_MAX_ATTEMPTS attempts.
    """
    last_exc = None
    for attempt in range(1, _NET_MAX_ATTEMPTS + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if not _is_transient_network_error(exc):
                raise
            if attempt >= _NET_MAX_ATTEMPTS:
                break
            backoff = _NET_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                f"[Codex] {label} Temporary network error ({type(exc).__name__}: {str(exc)[:120]}),"
                f"{backoff:.1f}s retrying afterwards (attempt {attempt}/{_NET_MAX_ATTEMPTS})..."
            )
            time.sleep(backoff)
    raise last_exc if last_exc else RuntimeError(f"[Codex] {label} Retries exhausted without an exception record")


def _with_auth_navigation_retry(session: BrowserSession, label: str, fn):
    """Retry 403/429/5xx of the Auth document, keeping the current Cookie/device context."""
    last_exc = None
    for attempt in range(1, _NET_MAX_ATTEMPTS + 1):
        try:
            resp = fn()
            status = int(getattr(resp, "status_code", 0) or 0)
            if status >= 400:
                error = RuntimeError(
                    f"{label} status={status}, body={(getattr(resp, 'text', '') or '')[:180]}"
                )
                error.response = resp
                raise error
            return resp
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_authorize_error(exc) or attempt >= _NET_MAX_ATTEMPTS:
                raise
            # Cloudflare 403 often updates __cf_bm at the same time. Only clear the local circuit breaker, and never
            # create a new Session, otherwise the Cookie just obtained and the unified device/session ID would be lost.
            _reset_retryable_circuit(session)
            backoff = _NET_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                "[Codex] %s temporary failure (%s/%s): %s: %s; "
                "keeping the current session/deviceId/CF Cookie, retrying in %.1fs",
                label, attempt, _NET_MAX_ATTEMPTS, type(exc).__name__,
                str(exc)[:160], backoff,
            )
            time.sleep(backoff)
    raise last_exc if last_exc else RuntimeError(f"[Codex] {label} retries exhausted")


def _codex_auth_preflight(session: BrowserSession) -> None:
    """Only warm up the Auth domain Codex really depends on; the ChatGPT home page is no longer a hard gate."""
    headers = session.get_auth_navigate_headers(
        referer="", user_initiated=False, target_origin="https://auth.openai.com",
    )
    logger.info("[Codex][pre-check] Auth document (unified session/deviceId)")
    _with_auth_navigation_retry(
        session,
        "auth document pre-check",
        lambda: session.get(
            "https://auth.openai.com/log-in",
            headers=headers,
            allow_redirects=True,
        ),
    )


def _codex_protocol_fingerprint_warmup(session: BrowserSession) -> None:
    """Warm up the ChatGPT Web fingerprint, version information and anonymous Cookies with the same protocol session."""
    logger.info("[Codex][fingerprint warm-up] Start: ChatGPT document + anonymous front-end initialization")
    headers = session.get_chatgpt_navigate_headers(referer="", user_initiated=False)
    resp = _with_auth_navigation_retry(
        session,
        "ChatGPT fingerprint document warm-up",
        lambda: session.get(
            "https://chatgpt.com/auth/login",
            headers=headers,
            allow_redirects=True,
        ),
    )
    observe = getattr(session, "observe_chatgpt_document", None)
    if callable(observe):
        observe(resp)

    # Reuse the anonymous initialization already done by the registration protocol chain, so oai-did, locale and the real front-end build
    # Cookie Jar share the same network and browser identity context as the following Auth OAuth navigation.
    from core.chatgpt_bootstrap import anonymous_bootstrap
    anonymous_bootstrap(session, strict=False)
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    logger.info("[Codex][fingerprint warm-up] Done, continuing with the Auth document pre-check")


def _codex_result(
    *,
    status: str,
    ok: bool = False,
    http_status: int | None = None,
    email: str | None = None,
    file_path: str | None = None,
    callback_url: str | None = None,
    message: str = "",
) -> dict:
    """Build a structured result of the same shape as flow_trigger._flow_result."""
    return {
        "status": status,
        "ok": ok,
        "http_status": http_status,
        "email": email,
        "file_path": file_path,
        "callback_url": callback_url,
        "message": message,
    }


def _account_registration_password(email: str) -> str:
    """Read the registration password of the account; return an empty string if there is none."""
    try:
        acc = db.get_account_by_email(email)
        if not acc:
            return ""
        extra_raw = acc.get("extra_json")
        extra = {}
        if isinstance(extra_raw, str) and extra_raw.strip():
            try:
                extra = json.loads(extra_raw)
            except Exception:
                extra = {}
        elif isinstance(extra_raw, dict):
            extra = extra_raw
        return str(extra.get("registration_password") or acc.get("registration_password") or "").strip()
    except Exception:
        return ""


def _account_totp_secret(email: str) -> str:
    """Read the 2FA secret enabled for the account; return an empty string if there is none."""
    try:
        acc = db.get_account_by_email(email)
        if not acc:
            return ""
        return str(acc.get("totp_secret") or "").strip()
    except Exception:
        return ""


def _account_totp_code(email: str) -> str:
    secret = _account_totp_secret(email)
    return pyotp.TOTP(secret).now() if secret else ""


# ============================================================
# PKCE / state(compare CLIProxyAPI pkce.go)
# ============================================================

def _generate_pkce() -> tuple[str, str]:
    """Generate a PKCE code pair: verifier=base64url(96 bytes), challenge=base64url(sha256(verifier))."""
    verifier_bytes = secrets.token_bytes(96)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _generate_state() -> str:
    """Generate a random OAuth state string against CSRF."""
    return secrets.token_urlsafe(32)


def _build_authorize_url(state: str, code_challenge: str, prompt: str = "login") -> str:
    """Assemble the Codex authorization URL with the parameter set of CLIProxyAPI openai_auth.go."""
    params = {
        "client_id": _cfg.CODEX_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": _cfg.CODEX_REDIRECT_URI,
        "scope": _cfg.CODEX_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": prompt,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    return f"{_cfg.CODEX_AUTH_URL}?{urlencode(params)}"


def _ensure_oai_context_url(auth_url: str, session: BrowserSession) -> str:
    """Add the front-end same-origin context parameters to the Codex OAuth authorization URL, keeping oai-did continuous."""
    try:
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        changed = False
        additions = {
            "ext-oai-did": session.device_id,
            "auth_session_logging_id": session.auth_session_logging_id,
            "screen_hint": "login_or_signup",
        }
        for key, value in additions.items():
            if not params.get(key):
                params[key] = [value]
                changed = True
        if not changed:
            return auth_url
        query = urlencode(params, doseq=True)
        return parsed._replace(query=query).geturl()
    except Exception:
        return auth_url


# ============================================================
# CPA management API: the authorization URL is generated by CPA and the successful callback is submitted to CPA CPA
# ============================================================

def _codex_auth_url_source() -> str:
    return str(getattr(_cfg, "CODEX_AUTH_URL_SOURCE", "cpa") or "cpa").strip().lower()


def _cpa_management_origin() -> str:
    raw = str(getattr(_cfg, "CPA_MANAGEMENT_URL", "") or "").strip()
    if not raw:
        raise RuntimeError("[Codex][CPA] not configured yet CPA_MANAGEMENT_URL")
    try:
        parsed = urlparse(raw)
    except Exception as exc:
        raise RuntimeError(f"[Codex][CPA] CPA_MANAGEMENT_URL invalid format: {raw}") from exc
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(f"[Codex][CPA] CPA_MANAGEMENT_URL invalid format: {raw}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _cpa_management_key() -> str:
    key = str(getattr(_cfg, "CPA_MANAGEMENT_KEY", "") or "").strip()
    if not key:
        raise RuntimeError("[Codex][CPA] not configured yet CPA_MANAGEMENT_KEY")
    return key


def _cpa_request_json(method: str, path: str, body: dict | None = None) -> dict:
    """Call the CPA management API, compatible with the /v0/management/* protocol of FlowPilot."""
    origin = _cpa_management_origin()
    key = _cpa_management_key()
    timeout = int(getattr(_cfg, "CPA_REQUEST_TIMEOUT", 30) or 30)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "X-Management-Key": key,
    }
    url = f"{origin}{path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=headers,
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            if isinstance(payload, dict):
                msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            raise RuntimeError(
                f"[Codex][CPA] management API failed {method.upper()} {path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        return payload if isinstance(payload, dict) else {}
    finally:
        try:
            session.close()
        except Exception:
            pass


def _sub2_codex_base() -> str:
    from config import sub2api as _sub2_cfg
    raw = str(
        getattr(_sub2_cfg, "SUB2API_API_BASE", "")
        or getattr(_sub2_cfg, "SUB2_CODEX_API_BASE", "")
        or ""
    ).strip().rstrip("/")
    if not raw:
        raise RuntimeError("[Codex][sub2] not configured yet SUB2API_API_BASE")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(f"[Codex][sub2] SUB2API_API_BASE invalid format: {raw}")
    return raw


def _sub2_codex_headers() -> dict:
    from config import sub2api as _sub2_cfg
    token = str(getattr(_sub2_cfg, "SUB2_CODEX_API_TOKEN", "") or getattr(_sub2_cfg, "SUB2API_API_KEY", "") or getattr(_sub2_cfg, "SUB2API_API_TOKEN", "") or "").strip()
    auth_header = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_HEADER", "") or getattr(_sub2_cfg, "SUB2API_API_AUTH_HEADER", "x-api-key") or "x-api-key").strip()
    auth_prefix = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_PREFIX", "") or getattr(_sub2_cfg, "SUB2API_API_AUTH_PREFIX", "") or "").strip()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "turb-gpt-free-register/codex-sub2",
    }
    if token:
        headers[auth_header] = f"{auth_prefix} {token}".strip() if auth_prefix else token
    return headers


def _sub2_codex_request_json(method: str, path: str, body: dict | None = None) -> dict:
    from config import sub2api as _sub2_cfg
    base = _sub2_codex_base()
    timeout = int(getattr(_sub2_cfg, "SUB2API_API_TIMEOUT", 20) or 20)
    normalized_path = "/" + str(path or "").lstrip("/")
    url = f"{base}{normalized_path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=_sub2_codex_headers(),
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            if isinstance(payload, dict):
                msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            raise RuntimeError(
                f"[Codex][sub2] API failed {method.upper()} {normalized_path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        return payload if isinstance(payload, dict) else {}
    finally:
        try:
            session.close()
        except Exception:
            pass


def _request_sub2_authorize_url() -> dict:
    """Generate the Codex OAuth authorization URL from sub2; PKCE is not generated locally."""
    from config import sub2api as _sub2_cfg
    path = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_URL_PATH", "/api/v1/admin/openai/generate-auth-url") or "/api/v1/admin/openai/generate-auth-url")
    logger.info("[Codex][sub2] Generating the authorization URL through the sub2 API...")
    payload = _sub2_codex_request_json("POST", path, {})
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    auth_url = _first_non_empty(
        payload.get("url"), payload.get("auth_url"), payload.get("authUrl"),
        data.get("url"), data.get("auth_url"), data.get("authUrl"),
    )
    session_id = _first_non_empty(
        payload.get("session_id"), payload.get("sessionId"),
        data.get("session_id"), data.get("sessionId"),
    )
    state = _first_non_empty(
        payload.get("state"), payload.get("auth_state"), payload.get("authState"),
        data.get("state"), data.get("auth_state"), data.get("authState"),
        _extract_state_from_auth_url(auth_url),
    )
    if not auth_url.startswith("http"):
        raise RuntimeError(f"[Codex][sub2] sub2 did not return a valid auth_url: {payload}")
    if not state:
        raise RuntimeError("[Codex][sub2] authorization URL is missing state")
    logger.info("[Codex][sub2] Authorization URL obtained,state=%s...", state[:12])
    logger.info("[Codex][sub2] Full authorization URL: %s", auth_url)
    if not session_id:
        logger.warning("[Codex][sub2] The authorization URL response lacks session_id, the later exchange-code may fail")
    return {"auth_url": auth_url, "state": state, "session_id": session_id, "origin": _sub2_codex_base(), "raw": payload}


def _summarize_sub2_response(payload: dict) -> str:
    """Compress the sub2api response log to avoid flooding the screen, while keeping the key account-creation information."""
    try:
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        parts = []
        if isinstance(data, dict):
            for key in ("id", "account_id", "name", "email", "platform", "type"):
                val = data.get(key)
                if val not in (None, ""):
                    parts.append(f"{key}={val}")
        if parts:
            return " ".join(parts)
        if isinstance(payload, dict):
            compact = {k: payload.get(k) for k in ("code", "message", "success") if k in payload}
            return str(compact or payload)[:300]
    except Exception:
        pass
    return str(payload)[:300]


def _submit_sub2_callback(callback_url: str, *, session_id: str = "", redirect_uri: str = "") -> dict:
    """Submit the OAuth callback to sub2."""
    from config import sub2api as _sub2_cfg
    path = str(getattr(_sub2_cfg, "SUB2_CODEX_CALLBACK_PATH", "/api/v1/admin/openai/create-from-oauth") or "/api/v1/admin/openai/create-from-oauth")
    mode = str(getattr(_sub2_cfg, "SUB2_CODEX_CALLBACK_PAYLOAD_MODE", "create_from_oauth") or "create_from_oauth").strip().lower()
    if mode == "callback_url":
        body = {"callback_url": str(callback_url or "").strip()}
    elif mode == "redirect_url":
        body = {"redirect_url": str(callback_url or "").strip()}
    else:
        parsed = urlparse(str(callback_url or ""))
        qs = parse_qs(parsed.query)
        code = (qs.get("code") or [""])[0]
        state = (qs.get("state") or [""])[0]
        if not session_id:
            raise RuntimeError("[Codex][sub2] exchange-code missing session_id")
        if not code:
            raise RuntimeError(f"[Codex][sub2] callback_url missing code: {callback_url}")
        if not state:
            raise RuntimeError(f"[Codex][sub2] callback_url missing state: {callback_url}")
        body = {"session_id": session_id, "code": code, "state": state}
        if redirect_uri:
            body["redirect_uri"] = redirect_uri
        if mode in {"create_from_oauth", "create-from-oauth", "create_oauth_account"}:
            body.setdefault("concurrency", 3)
            body.setdefault("priority", 50)

    max_attempts = max(1, int(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRIES", 5) or 5))
    base_delay = max(1.0, float(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRY_DELAY", 6) or 6))
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info("[Codex][sub2] Uploading the OAuth callback (attempt %s/%s)... callback=%s", attempt, max_attempts, callback_url)
            payload = _sub2_codex_request_json("POST", path, body)
            logger.info("[Codex][sub2] callback uploaded and processed (succeeded on attempt %s) response=%s", attempt, _summarize_sub2_response(payload))
            return payload
        except Exception as exc:
            last_exc = exc
            retryable = _is_cpa_callback_retryable(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning("[Codex][sub2] callback upload failed and will not be retried:attempt=%s/%s retryable=%s error=%s", attempt, max_attempts, retryable, exc)
                raise
            delay = base_delay * attempt
            logger.warning("[Codex][sub2] callback upload failed, will retry in %.1fs:attempt=%s/%s error=%s", delay, attempt, max_attempts, exc)
            time.sleep(delay)
    raise RuntimeError(f"[Codex][sub2] callback upload failed:{last_exc}")



def _cpa_request_raw(method: str, path: str, body: dict | None = None, *, response_type: str = "text"):
    """Call the CPA management API and return the raw response; used for non-JSON responses such as downloading auth-files."""
    origin = _cpa_management_origin()
    key = _cpa_management_key()
    timeout = int(getattr(_cfg, "CPA_REQUEST_TIMEOUT", 30) or 30)
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "X-Management-Key": key,
    }
    url = f"{origin}{path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=headers,
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            try:
                payload = resp.json()
                if isinstance(payload, dict):
                    msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            except Exception:
                pass
            raise RuntimeError(
                f"[Codex][CPA] management API failed {method.upper()} {path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        if response_type == "bytes":
            return resp.content
        return resp.text
    finally:
        try:
            session.close()
        except Exception:
            pass


def list_cpa_codex_auth_files() -> list[dict]:
    """Read the CPA auth-files list and return only credentials whose type/name/email identify them as codex."""
    payload = _cpa_request_json("GET", "/v0/management/auth-files")
    files = payload.get("files") if isinstance(payload.get("files"), list) else []
    out = []
    for item in files:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        ftype = str(item.get("type") or "").strip().lower()
        email = str(item.get("email") or "").strip().lower()
        if ftype == "codex" or name.lower().startswith("codex-") or "codex" in name.lower():
            copied = dict(item)
            copied["name"] = name
            copied["email"] = email or str(item.get("email") or "")
            out.append(copied)
    return out


def find_cpa_codex_auth_file(*, email: str = "", local_filename: str = "") -> dict | None:
    """Match the CPA-side codex auth file by local receipt / credential file name or email."""
    email_l = str(email or "").strip().lower()
    local_name_l = str(local_filename or "").strip().lower()
    local_stem_l = local_name_l[:-5] if local_name_l.endswith(".json") else local_name_l
    files = list_cpa_codex_auth_files()
    if not files:
        return None

    def score(item: dict) -> int:
        name_l = str(item.get("name") or "").lower()
        item_email_l = str(item.get("email") or "").lower()
        s = 0
        if local_name_l and name_l == local_name_l:
            s = max(s, 100)
        if local_stem_l and name_l.startswith(local_stem_l):
            s = max(s, 80)
        if email_l and item_email_l == email_l:
            s = max(s, 70)
        if email_l and email_l in name_l:
            s = max(s, 60)
        # The local CPA receipt name is usually codex-email-cpa-callback.json, while the actual CPA file is codex-email-free.json.
        if local_stem_l.endswith("-cpa-callback"):
            base = local_stem_l[:-len("-cpa-callback")]
            if base and name_l.startswith(base + "-"):
                s = max(s, 75)
        return s

    ranked = sorted(((score(item), item) for item in files), key=lambda x: x[0], reverse=True)
    return ranked[0][1] if ranked and ranked[0][0] > 0 else None


def download_cpa_codex_auth_text(*, cpa_name: str | None = None, email: str = "", local_filename: str = "") -> tuple[str, str, dict]:
    """
    Download one Codex JSON text from the CPA auth-files.
    Returns: (content_text, download_filename, matched_file_meta)
    """
    meta = None
    name = str(cpa_name or "").strip()
    if name:
        # When the CPA file name is already known, download directly without fetching the auth-files list one more time.
        # A batch download from the account list lists once up front; listing again here would make the browser wait a long time for the download confirmation when many accounts are selected.
        meta = {"name": name}
    else:
        meta = find_cpa_codex_auth_file(email=email, local_filename=local_filename)
        name = str((meta or {}).get("name") or "").strip()
    if not name:
        target = email or local_filename or cpa_name or "unknown"
        raise RuntimeError(f"[Codex][CPA] No matching Codex credential found in the CPA auth-files: {target}")
    text = _cpa_request_raw("GET", f"/v0/management/auth-files/download?name={quote(name, safe='')}", response_type="text")
    # The download endpoint should normally return JSON text; a light validation is done here, to avoid exporting HTML/error text as a credential.
    try:
        parsed = json.loads(text)
    except Exception as exc:
        raise RuntimeError(f"[Codex][CPA] CPA downloaded content is not valid JSON: {name}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"[Codex][CPA] CPA downloaded content is not a JSON object: {name}")
    return json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", name, (meta or {"name": name})

def _first_non_empty(*values) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _extract_state_from_auth_url(auth_url: str) -> str:
    try:
        return parse_qs(urlparse(auth_url).query).get("state", [""])[0]
    except Exception:
        return ""


def _request_cpa_authorize_url() -> dict:
    """Generate the Codex OAuth authorization URL from CPA; PKCE is not generated locally."""
    logger.info("[Codex][CPA] Generating the authorization URL through the CPA management API...")
    payload = _cpa_request_json("GET", "/v0/management/codex-auth-url")
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    auth_url = _first_non_empty(
        payload.get("url"),
        payload.get("auth_url"),
        payload.get("authUrl"),
        data.get("url"),
        data.get("auth_url"),
        data.get("authUrl"),
    )
    state = _first_non_empty(
        payload.get("state"),
        payload.get("auth_state"),
        payload.get("authState"),
        data.get("state"),
        data.get("auth_state"),
        data.get("authState"),
        _extract_state_from_auth_url(auth_url),
    )
    if not auth_url.startswith("http"):
        raise RuntimeError(f"[Codex][CPA] CPA did not return a valid auth_url: {payload}")
    if not state:
        raise RuntimeError("[Codex][CPA] CPA authorization URL is missing state")
    logger.info(f"[Codex][CPA] Authorization URL obtained,state={state[:12]}...")
    logger.info(f"[Codex][CPA] Full authorization URL: {auth_url}")
    return {
        "auth_url": auth_url,
        "state": state,
        "origin": _cpa_management_origin(),
        "raw": payload,
    }


def _is_cpa_callback_retryable(exc: Exception) -> bool:
    text = str(exc or "").lower()
    return (
        "status=409" in text
        or "timeout waiting for oauth callback" in text
        or "timeout" in text
        or "timed out" in text
        or "connection" in text
        or "status=429" in text
        or "status=500" in text
        or "status=502" in text
        or "status=503" in text
        or "status=504" in text
    )


def _is_cpa_callback_reauth_error(exc_or_text) -> bool:
    """CPA If it still returns 409 timeout after the callback was received, the authorization URL usually has to be regenerated and a new round of OAuth run."""
    text = str(exc_or_text or "").lower()
    return (
        "oauth-callback" in text
        and "status=409" in text
        and "timeout waiting for oauth callback" in text
    ) or (
        "timeout waiting for oauth callback" in text
    )


def _submit_cpa_callback(callback_url: str) -> dict:
    """Submit the OAuth callback to CPA.

    CPA occasionally still returns after the browser already got the localhost callback
    “409 Timeout waiting for OAuth callback”, usually a race of the management side waiting / storing;
    Here the same callback URL is retried several times, and the authorization URL is not regenerated.
    """
    body = {
        "provider": "codex",
        "redirect_url": str(callback_url or "").strip(),
    }
    max_attempts = max(1, int(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRIES", 5) or 5))
    base_delay = max(1.0, float(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRY_DELAY", 6) or 6))
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                "[Codex][CPA] Submitting the OAuth callback to CPA (attempt %s/%s)... callback=%s",
                attempt, max_attempts, str(callback_url or "")
            )
            payload = _cpa_request_json("POST", "/v0/management/oauth-callback", body)
            logger.info("[Codex][CPA] callback submitted (succeeded on attempt %s)", attempt)
            return payload
        except Exception as exc:
            last_exc = exc
            retryable = _is_cpa_callback_retryable(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[Codex][CPA] callback submit failed and will not be retried:attempt=%s/%s retryable=%s error=%s",
                    attempt, max_attempts, retryable, exc
                )
                raise
            delay = base_delay * attempt
            logger.warning(
                "[Codex][CPA] callback submit failed, will retry in %.1fs:attempt=%s/%s error=%s",
                delay, attempt, max_attempts, exc
            )
            time.sleep(delay)
    raise RuntimeError(f"[Codex][CPA] callback submit failed:{last_exc}")


# ============================================================
# Helpers: judge/parse
# ============================================================

def _is_redirect_uri(location: str) -> bool:
    """Judge whether the Location points to the registered redirect_uri (localhost:1455/auth/callback)."""
    try:
        parsed = urlparse(location)
    except Exception:
        return False
    return parsed.scheme in ("http", "https") and \
        parsed.hostname in ("localhost", "127.0.0.1") and \
        parsed.port == 1455 and \
        parsed.path == "/auth/callback"


def _extract_code(location: str, state: str) -> str:
    """Extract and validate the code from the Location of the redirect_uri."""
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    err = (qs.get("error") or [""])[0]
    if err:
        err_desc = (qs.get("error_description") or [""])[0]
        raise RuntimeError(f"[Codex] authorization server returned an error: error={err}, desc={err_desc}")
    code = (qs.get("code") or [""])[0]
    if not code:
        raise RuntimeError(f"[Codex] redirect_uri missing code parameter: {location}")
    returned_state = (qs.get("state") or [""])[0]
    if returned_state and returned_state != state:
        raise RuntimeError(
            f"[Codex] state mismatch (suspected CSRF): expected={state[:8]}..., got={returned_state[:8]}..."
        )
    return code


def _decode_jwt_segment(seg: str) -> dict:
    """base64url Decode a JWT/cookie segment into a JSON dict (returns {} on failure)."""
    try:
        padding = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + padding))
    except Exception:
        return {}


def _post_json(session: BrowserSession, url: str, payload: dict, referer: str,
               sentinel_header: str | None = None, so_header: str | None = None):
    """Uniformly send a JSON POST to /api/accounts/*."""
    headers = session.get_auth_headers(referer=referer)
    if sentinel_header:
        headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    resp = session.post(url, headers=headers, data=json.dumps(payload), allow_redirects=False)
    _cache_auth_session_metadata(session, resp)
    return resp


def _resp_json(resp) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}


def _response_text(resp) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict):
            parts = []
            def walk(x):
                if isinstance(x, dict):
                    for v in x.values(): walk(v)
                elif isinstance(x, list):
                    for v in x: walk(v)
                elif x is not None:
                    parts.append(str(x))
            walk(data)
            return " ".join(parts)
    except Exception:
        pass
    return str(getattr(resp, 'text', '') or '')


def _decode_auth_session_metadata(value) -> dict:
    """Convert the oai-client-auth-session in the response into a workspace payload."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    return _decode_jwt_segment(value.split(".", 1)[0])


def _cache_auth_session_metadata(session: BrowserSession, resp) -> None:
    """Cache the session metadata carried by the Auth response, to restore the workspace when the cookie is missing."""
    try:
        payload = _resp_json(resp)
        if not isinstance(payload, dict):
            return
        value = payload.get("oai-client-auth-session")
        if value is None:
            value = payload.get("auth_session") or payload.get("authSession")
        cached = _decode_auth_session_metadata(value)
        if cached:
            session._codex_auth_session_payload = cached
    except Exception:
        logger.debug("[Codex] Failed to cache the Auth session metadata", exc_info=True)


def _phone_failure_reason(text: str, status_code: int | None = None) -> str:
    low = str(text or '').lower()
    if 'whatsapp' in low or 'whats app' in low:
        return 'whatsapp_channel'
    if any(k in low for k in (
        'phone number is not valid', 'invalid phone number', 'invalid phone', 'not a valid phone',
        '号码无效', '手机号无效', '电话号码无效', 'invalid_number', 'invalid_phone',
    )):
        return 'invalid_phone'
    if any(k in low for k in (
        'cannot send', "can't send", 'could not send', "couldn't send", 'unable to send',
        'cannot deliver', 'unable to deliver', 'failed to send', 'send failed',
        '无法发送', '不能发送', '无法向', '发送验证码', '发送短信',
    )):
        return 'delivery_refused'
    if any(k in low for k in ('too many', 'rate limit', 'throttle', 'limited', '频繁', '限流')):
        return 'send_limited'
    if any(k in low for k in ('already used', 'used too many', 'maximum', '上限', '已被使用')):
        return 'phone_used_or_max'
    if status_code and status_code >= 500:
        return 'server_error'
    if status_code and status_code >= 400:
        return 'send_rejected'
    return ''


# ============================================================
# Step 0: follow the Codex authorize URL with a brand new session and establish the auth.openai.com session
# ============================================================

def _bootstrap_authorize(
    session: BrowserSession,
    state: str,
    code_challenge: str | None = None,
    auth_url: str | None = None,
) -> None:
    """
    GET Codex authorize URL and follow the redirects, landing on the login page, and establish auth.openai.com cookies
    (including oai-client-auth-session: it contains the Codex target + the workspace list needed later).
    """
    # By default the CPA authorization URL passed in by the caller is used; the retained local PKCE generation logic is only used when none is passed.
    if not auth_url:
        if not code_challenge:
            raise RuntimeError("[Codex] Generating the authorization URL locally requires code_challenge")
        auth_url = _build_authorize_url(state, code_challenge, prompt="login")
    auth_url = _ensure_oai_context_url(auth_url, session)
    # Codex CLI/CPA The authorization URL is a top-level navigation the user opens directly from an external client, not coming from
    # chatgpt.com a page click. Use sec-fetch-site:none and do not forge a Referer.
    headers = session.get_auth_navigate_headers(referer="", user_initiated=True)
    logger.info("[Codex] Following the Codex authorize URL to establish the session...")
    logger.info(f"[Codex] Full authorization URL: {auth_url}")
    resp = _with_auth_navigation_retry(
        session,
        "bootstrap authorize",
        lambda: session.get(auth_url, headers=headers, allow_redirects=True),
    )
    logger.debug(f"[Codex] authorize landing point: {getattr(resp, 'url', '')}, status={getattr(resp, 'status_code', '')}")


# ============================================================
# Step 1: submit the email (triggers the email OTP send)
# ============================================================

def _submit_email(session: BrowserSession, email: str) -> dict:
    """POST authorize/continue Submit the email so that the Auth service returns the next step (password page / OTP page etc.). Carries sentinel."""
    sentinel_resp = request_sentinel_token(session, "authorize_continue")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "authorize_continue")
    payload = {"username": {"kind": "email", "value": email}}
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/authorize/continue",
        payload,
        referer="https://auth.openai.com/log-in",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code not in (200, 204):
        raise RuntimeError(
            f"[Codex] submitting the email failed status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    result = _resp_json(resp)
    logger.info(
        "[Codex] Submitted email %s, Auth next step:page=%s continue=%s",
        email,
        _page_type(result) or "-",
        _extract_continue_url(result) or "-",
    )
    return result


def _extract_continue_url(result: dict | None) -> str:
    """Extract the continue/redirect URL from the Auth JSON response."""
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    page = page if isinstance(page, dict) else {}
    return str(
        result.get("continue_url")
        or result.get("external_url")
        or result.get("redirect_url")
        or result.get("url")
        or page.get("continue_url")
        or page.get("external_url")
        or page.get("redirect_url")
        or page.get("url")
        or ""
    ).strip()


def _extract_factor_id(result: dict | None, continue_url: str = "") -> str:
    """Extract factor_id from the MFA response or /mfa-challenge/<factor_id> URL URL."""
    if isinstance(result, dict):
        factor_id = str(result.get("factor_id") or result.get("id") or "").strip()
        if factor_id:
            return factor_id
        page = result.get("page") or {}
        page = page if isinstance(page, dict) else {}
        payload = page.get("payload") or {}
        if isinstance(payload, dict):
            factor_id = str(payload.get("factor_id") or payload.get("id") or "").strip()
            if factor_id:
                return factor_id
    if "/mfa-challenge/" in continue_url:
        return continue_url.rstrip("/").rsplit("/", 1)[-1]
    return ""


def _page_type(result: dict | None) -> str:
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    return str((page if isinstance(page, dict) else {}).get("type") or "").strip()


def _result_text(result: dict | None) -> str:
    """Flatten the nested result returned by Auth into matchable text, without depending on a single field name."""
    try:
        return json.dumps(result or {}, ensure_ascii=False, separators=(",", ":")).lower()
    except Exception:
        return str(result or "").lower()


def _result_has_any(result: dict | None, *terms: str) -> bool:
    text = _result_text(result)
    return any(str(term).lower() in text for term in terms)


def _is_password_step(result: dict | None) -> bool:
    return _result_has_any(
        result,
        "log-in/password",
        "login/password",
        "password_verify",
        '"page":"password"',
        '"type":"password"',
        '"type":"login_password"',
    )


def _is_email_otp_step(result: dict | None) -> bool:
    return _result_has_any(
        result,
        "email-verification",
        "email_otp",
        "email-otp",
        "email_otp_send",
    )


def _is_mfa_step(result: dict | None, continue_url: str = "") -> bool:
    return "/mfa-challenge/" in str(continue_url or "").lower() or _result_has_any(
        result,
        "mfa-challenge",
        "mfa_challenge",
        "totp",
        '"type":"mfa"',
    )


def _is_phone_step(result: dict | None) -> bool:
    return _result_has_any(
        result,
        "add-phone",
        "add_phone",
        "phone-verification",
        "phone_verification",
        "phone_otp",
    )


def _password_verify(session: BrowserSession, password: str) -> dict:
    """Submit the login password."""
    sentinel_resp = request_sentinel_token(session, "password_verify")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "password_verify")
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/password/verify",
        {"password": password},
        referer="https://auth.openai.com/log-in/password",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"[Codex] password verification failed status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    logger.info("[Codex] password verification passed")
    return _resp_json(resp)


def _mfa_issue_challenge(session: BrowserSession, factor_id: str) -> dict:
    """Start a TOTP MFA challenge."""
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/mfa/issue_challenge",
        {"id": factor_id, "type": "totp", "force_fresh_challenge": False},
        referer="https://auth.openai.com/mfa-challenge",
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"[Codex] MFA challenge start failed status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    return _resp_json(resp)


def _mfa_verify(session: BrowserSession, factor_id: str, code: str) -> dict:
    """Submit the TOTP MFA verification code."""
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/mfa/verify",
        {"id": factor_id, "type": "totp", "code": code},
        referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
    )
    if resp.status_code != 200:
        # MFA For deleted/disabled accounts the API sometimes only returns a natural-language message,
        # without the account_deactivated error code; it is uniformly converted into an unrecoverable state,
        # so the rerun service does not keep retrying such accounts.
        error_code = _extract_error_code(resp)
        if not error_code:
            error_code = detect_account_unusable_response_body(resp.text or "")
        if not error_code:
            error_code = detect_account_unusable_text(resp.text or "")
        if error_code:
            raise AccountUnusableError(
                f"[Codex] Account is dead ({error_code})MFA status={resp.status_code}: {(resp.text or '')[:240]}",
                error_code=error_code,
            )
        raise RuntimeError(
            f"[Codex] MFA verification failed status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    logger.info("[Codex] MFA/TOTP verification passed")
    return _resp_json(resp)


def _complete_mfa_if_required(session: BrowserSession, email: str, result: dict | None) -> dict:
    """Only when the current Auth result explicitly requires MFA, submit the account TOTP and return the next state."""
    continue_url = _extract_continue_url(result)
    if not _is_mfa_step(result, continue_url):
        return result or {}

    factor_id = _extract_factor_id(result, continue_url)
    if not factor_id:
        raise RuntimeError(f"[Codex] Auth requires MFA, but no factor_id was obtained:{result}")
    code = _account_totp_code(email)
    if not code:
        raise RuntimeError(f"[Codex] Auth requires MFA, but the account has no usable totp_secret:{email}")

    logger.info("[Codex] Auth requires MFA, starting to submit the account TOTP:%s factor_id=%s", email, factor_id)
    _mfa_issue_challenge(session, factor_id)
    return _mfa_verify(session, factor_id, code)


def _follow_login_continue(session: BrowserSession, continue_url: str, state: str) -> str | None:
    """
    After a password/MFA success the continue URL may jump straight to the callback, or may only advance the session to
    Codex consent/workspace page. Here we only follow the redirects and keep the Cookies:
      - hit the localhost callback: return callback URL
      - Stopped at a 200 HTML / no Location: return None, continue afterwards workspace/select
    """
    if not continue_url:
        return None
    url = continue_url if continue_url.startswith("http") else ("https://auth.openai.com" + continue_url)
    for hop in range(_MAX_REDIRECTS):
        if _is_redirect_uri(url):
            return url
        headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/", user_initiated=True)
        resp = session.get(url, headers=headers, allow_redirects=False)
        loc = resp.headers.get("location") or resp.headers.get("Location")
        logger.debug(
            "[Codex] login continue following hop %s: status=%s, location=%s",
            hop, getattr(resp, "status_code", ""), loc,
        )
        if not loc:
            return None
        url = loc if loc.startswith("http") else ("https://auth.openai.com" + loc)
    raise RuntimeError(f"[Codex] Login continue following exceeded {_MAX_REDIRECTS} hops")


def _try_password_mfa_login(
    session: BrowserSession,
    email: str,
    state: str,
    initial_result: dict | None,
) -> tuple[str, str | None, dict]:
    """
    With a registration password, password login is preferred; if it enters an MFA challenge, the TOTP is generated from the account totp_secret.

    Return:
      ("logged_in", callback_url_or_None, result)  password/MFA login completed
      ("email_otp", None, result)                  the server requires email OTP
      ("not_applicable", None, result)            The actual current page is not the password page
    """
    password = _account_registration_password(email)
    if not password or not _is_password_step(initial_result):
        logger.info(
            "[Codex] The current Auth does not require a password, continuing as returned by the server:email=%s page=%s continue=%s",
            email,
            _page_type(initial_result) or "-",
            _extract_continue_url(initial_result) or "-",
        )
        return "not_applicable", None, initial_result or {}

    logger.info("[Codex] The account has a registration password, preferring password login:%s", email)
    result = _password_verify(session, password)
    continue_url = _extract_continue_url(result)
    page_type = _page_type(result)

    if _is_mfa_step(result, continue_url) or page_type == "mfa_challenge":
        result = _complete_mfa_if_required(session, email, result)
        continue_url = _extract_continue_url(result) or continue_url
        page_type = _page_type(result)

    if _is_email_otp_step(result) or page_type in {"email_verification", "email_otp_send"}:
        logger.info("[Codex] After password login the server still requires the email OTP, switching to the email OTP:%s", email)
        return "email_otp", None, result

    callback_url = _follow_login_continue(session, continue_url, state) if continue_url else None
    logger.info("[Codex] The password/MFA login chain has completed, continuing with the Codex workspace/callback:%s", email)
    return "logged_in", callback_url, result


# ============================================================
# Step 2: submit the email OTP
# ============================================================

def _submit_email_otp(session: BrowserSession, code: str) -> dict:
    """POST email-otp/validate Submit the email verification code. Carries sentinel(authorize_continue)."""
    sentinel_resp = request_sentinel_token(session, "authorize_continue")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "authorize_continue")
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/email-otp/validate",
        {"code": code},
        referer="https://auth.openai.com/email-verification",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code != 200:
        error_code = _extract_error_code(resp)
        if error_code in ("account_deactivated", "account_deleted", "account_banned"):
            raise AccountUnusableError(
                f"[Codex] Account is dead ({error_code})status={resp.status_code}: {(resp.text or '')[:200]}",
                error_code=error_code,
            )
        body_error_code = detect_account_unusable_response_body(resp.text or "")
        if body_error_code:
            raise AccountUnusableError(
                f"[Codex] Account is dead ({body_error_code})status={resp.status_code}: {(resp.text or '')[:200]}",
                error_code=body_error_code,
            )
        raise RuntimeError(
            f"[Codex] email OTP verification failed status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    logger.info("[Codex] email OTP verification passed")
    result = _resp_json(resp)
    logger.info(
        "[Codex] Auth next step after the email OTP:page=%s continue=%s phone=%s mfa=%s",
        _page_type(result) or "-",
        _extract_continue_url(result) or "-",
        _is_phone_step(result),
        _is_mfa_step(result, _extract_continue_url(result)),
    )
    return result


# ============================================================
# Steps 3-4: phone number verification (code receiving, switch numbers and retry on failure)
# ============================================================

def _sms_provider_name() -> str:
    """Name of the current code-receiving channel, only used for the Codex flow logs."""
    return str(getattr(_cfg, "SMS_PROVIDER", "grizzly") or "grizzly").strip().lower()


def _sleep_before_phone_retry(attempt: int, max_retries: int, *, prefix: str = "[Codex]") -> None:
    """Wait a random time before switching numbers, at least 3 seconds, to avoid submitting numbers too quickly in a row."""
    if attempt >= max_retries:
        return
    seconds = random.uniform(3.0, 8.0)
    logger.info(f"{prefix} Waiting a random {seconds:.1f} seconds before switching numbers")
    time.sleep(seconds)


def _do_phone_verification(session: BrowserSession) -> dict:
    """
    Take a number from the code-receiving platform -> add-phone/send sends the SMS -> receive the code -> phone-otp/validate.
    If a number receives no code or is rejected by OpenAI, cancel it and switch numbers, at most SMS_MAX_RETRIES times (hot-reloaded).

    The actual platform adapters live in core.sms_provider:
        - SMS_PROVIDER="grizzly":GrizzlySMS handler_api.php
        - SMS_PROVIDER="l": the /take-phone and /fetch-code JSON APIs of L_API.md
    """
    http = sms_provider._http()
    max_retries = _cfg.SMS_MAX_RETRIES
    provider = _sms_provider_name()
    try:
        last_err = None
        for attempt in range(1, max_retries + 1):
            activation_id = None
            try:
                activation_id, phone = sms_provider.acquire_number(http)
                logger.info(
                    f"[Codex] Phone verification attempt {attempt}/{max_retries},"
                    f"provider={provider}, activation_id={activation_id}, number=+{phone}"
                )

                # Send the SMS
                send_resp = _post_json(
                    session,
                    "https://auth.openai.com/api/accounts/add-phone/send",
                    {"phone_number": f"+{phone}", "channel": "sms"},
                    referer="https://auth.openai.com/add-phone",
                )
                send_text = _response_text(send_resp)
                send_reason = _phone_failure_reason(send_text, send_resp.status_code)
                if send_resp.status_code not in (200, 204) or send_reason:
                    # Invalid number / cannot send / WhatsApp channel / rate limited etc. -> release the current number and switch numbers.
                    logger.warning(
                        f"[Codex] add-phone/send unsuccessful reason={send_reason or 'unknown'}, "
                        f"status={send_resp.status_code}: {send_text[:240]}, switching number to retry"
                    )
                    sms_provider.cancel(activation_id, http)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                # Tell the platform the SMS has been sent (status=1)
                sms_provider.set_status(activation_id, 1, http=http)

                # Poll the code-receiving platform for the SMS on a schedule. wait_for_sms_code polls internally every SMS_POLL_INTERVAL,
                # waiting at most SMS_CODE_WAIT; on timeout the current number is cancelled immediately and another number is used.
                try:
                    logger.info(
                        f"[Codex] SMS sent, starting to poll for the verification code activation_id={activation_id}, "
                        f"wait={_cfg.SMS_CODE_WAIT}s, interval={_cfg.SMS_POLL_INTERVAL}s"
                    )
                    sms_code = sms_provider.wait_for_sms_code(activation_id, http)
                except sms_provider.SmsCodeTimeout:
                    logger.warning(f"[Codex] Number +{phone} received no SMS within {_cfg.SMS_CODE_WAIT}s, cancelling and switching numbers")
                    sms_provider.cancel(activation_id, http)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                # Verify the phone code
                val_resp = _post_json(
                    session,
                    "https://auth.openai.com/api/accounts/phone-otp/validate",
                    {"code": sms_code},
                    referer="https://auth.openai.com/phone-verification",
                )
                if val_resp.status_code != 200:
                    val_text = _response_text(val_resp)
                    val_reason = _phone_failure_reason(val_text, val_resp.status_code) or 'code_rejected'
                    logger.warning(
                        f"[Codex] phone-otp/validate failed reason={val_reason}, status={val_resp.status_code}: "
                        f"{val_text[:240]}, switching number to retry"
                    )
                    sms_provider.cancel(activation_id, http)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                # Success
                sms_provider.complete(activation_id, http)
                logger.info("[Codex] Phone number verification passed")
                return _resp_json(val_resp)

            except sms_provider.SmsNoBalanceError:
                # Insufficient balance, retrying is pointless, raise directly
                raise
            except sms_provider.SmsProviderError as exc:
                last_err = exc
                logger.warning(f"[Codex] Code-receiving attempt {attempt} failed:{exc}")
                if activation_id:
                    sms_provider.cancel(activation_id, http)
                _sleep_before_phone_retry(attempt, max_retries)
                continue

        raise RuntimeError(
            f"[Codex] Phone verification still failed after {max_retries} retries (provider={provider})"
            + (f", last error:{last_err}" if last_err else "")
        )
    finally:
        http.close()


# ============================================================
# Step 5: pick the workspace -> get callback code
# ============================================================

def _get_workspace_id(session: BrowserSession) -> str:
    """
    Prefer decoding the workspace from the oai-client-auth-session cookie; when the cookie has not landed yet,
    fall back to the Auth response metadata, and wait for the cookie/response state within a bounded time.
    """
    def find_workspace_id(payload: dict) -> str:
        for workspace in payload.get("workspaces") or []:
            if isinstance(workspace, dict) and workspace.get("id"):
                return str(workspace["id"])
        return ""

    deadline = time.monotonic() + max(0.0, float(_WORKSPACE_COOKIE_WAIT_SECONDS))
    while True:
        raw = None
        try:
            for c in session.session.cookies.jar:
                if c.name == "oai-client-auth-session":
                    raw = c.value
                    break
        except Exception:
            pass
        if not raw:
            try:
                raw = session.session.cookies.get("oai-client-auth-session")
            except Exception:
                raw = None

        if raw:
            wid = find_workspace_id(_decode_auth_session_metadata(raw))
            if wid:
                logger.info(f"[Codex] workspace_id={wid}")
                return wid

        wid = find_workspace_id(getattr(session, "_codex_auth_session_payload", {}) or {})
        if wid:
            logger.info(f"[Codex] workspace_id={wid}(from the Auth response metadata)")
            return wid

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if not raw:
                raise RuntimeError("[Codex] Cannot find the oai-client-auth-session cookie, cannot get workspace_id")
            raise RuntimeError("[Codex] oai-client-auth-session has no usable workspace_id")
        time.sleep(min(_WORKSPACE_POLL_INTERVAL_SECONDS, remaining))


def _select_workspace_and_get_callback(session: BrowserSession, state: str) -> str:
    """
    POST workspace/select, then follow the following redirects / URLs in the responses until the localhost:1455 callback is hit.
    Return the full callback URL (including the code).
    """
    wid = _get_workspace_id(session)
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/workspace/select",
        {"workspace_id": wid},
        referer="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
    )

    # 1) Hit the callback directly with the Location header callback
    loc = resp.headers.get("location") or resp.headers.get("Location")
    if loc and _is_redirect_uri(loc):
        return loc

    # 2) The response JSON gives the next-step URL (continue_url / redirect_url / url / next)
    data = _resp_json(resp)
    next_url = None
    for key in ("redirect_url", "continue_url", "url", "next", "location"):
        v = data.get(key)
        if isinstance(v, str) and v:
            next_url = v
            break

    # 3) No URL given but there is a Location (not the callback) -> follow from the Location
    if not next_url and loc:
        next_url = loc

    if not next_url:
        raise RuntimeError(
            f"[Codex] workspace/select no next hop found afterwards, URL URL: status={resp.status_code}, "
            f"body={(resp.text or '')[:300]}"
        )

    # Follow the redirect chain until the callback
    return _follow_until_callback(session, next_url, state)


def _follow_until_callback(session: BrowserSession, url: str, state: str) -> str:
    """Follow hop by hop from the given URL, and return its Location when the localhost:1455 callback is hit."""
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    for hop in range(_MAX_REDIRECTS):
        if _is_redirect_uri(url):
            return url
        headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/")
        resp = session.get(url, headers=headers, allow_redirects=False)
        loc = resp.headers.get("location") or resp.headers.get("Location")
        logger.debug(f"[Codex] callback follow hop {hop}: status={getattr(resp,'status_code','')}, location={loc}")
        if loc is None:
            raise RuntimeError(
                f"[Codex] following interrupted, did not hit callback: url={url}, "
                f"status={getattr(resp,'status_code','')}, body={(resp.text or '')[:200]}"
            )
        if _is_redirect_uri(loc):
            return loc
        url = loc if loc.startswith("http") else ("https://auth.openai.com" + loc)
    raise RuntimeError(f"[Codex] Following the callback exceeded {_MAX_REDIRECTS} hops")


# ============================================================
# Exchange the token (compare CLIProxyAPI ExchangeCodeForTokensWithRedirect) - unchanged
# ============================================================

def exchange_codex_token(session: BrowserSession, code: str, code_verifier: str) -> dict:
    """Exchange the authorization code for a token."""
    data = {
        "grant_type": "authorization_code",
        "client_id": _cfg.CODEX_CLIENT_ID,
        "code": code,
        "redirect_uri": _cfg.CODEX_REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    base = session._get_common_headers()
    base.update(headers)
    headers = base

    logger.info("[Codex] Exchanging the authorization code for token...")
    resp = session.post(_cfg.CODEX_TOKEN_URL, headers=headers, data=urlencode(data))
    http_status = resp.status_code
    if http_status != 200:
        raise RuntimeError(
            f"[Codex] token exchange failed status={http_status}: {(resp.text or '')[:300]}"
        )
    token_resp = resp.json()
    if not token_resp.get("access_token"):
        raise RuntimeError(f"[Codex] token response is missing access_token: {token_resp}")
    logger.info(
        f"[Codex] token exchange succeeded,expires_in={token_resp.get('expires_in')}, "
        f"access_token={token_resp['access_token'][:16]}..."
    )
    return token_resp


# ============================================================
# Parse the id_token / persist - unchanged
# ============================================================

def _parse_id_token(id_token: str) -> dict:
    """base64 Decode the JWT payload (signature not verified) and extract email / account_id / plan_type."""
    if not id_token:
        return {}
    try:
        parts = id_token.split(".")
        if len(parts) < 2:
            return {}
        claims = _decode_jwt_segment(parts[1])
    except Exception as exc:
        logger.warning(f"[Codex] id_token parse failed: {exc}")
        return {}

    auth_claim = claims.get("https://api.openai.com/auth", {}) or {}
    profile_claim = claims.get("https://api.openai.com/profile", {}) or {}
    # OpenAI In the new id_token the email is a top-level claim; in the old version / CLIProxyAPI implementation it is inside profile_claim.
    # Top level first, otherwise fall back to profile_claim, so the email field in the persisted codex-email.json is not empty.
    email_value = claims.get("email") or profile_claim.get("email", "")
    return {
        "email": email_value,
        "account_id": auth_claim.get("chatgpt_account_id", ""),
        "plan_type": auth_claim.get("chatgpt_plan_type", ""),
    }


def build_codex_storage(token_resp: dict, id_claims: dict) -> dict:
    """Assemble the CLIProxyAPI CodexTokenStorage JSON structure."""
    expires_in = token_resp.get("expires_in", 0) or 0
    expired_dt = datetime.now(timezone.utc) + _timedelta_seconds(expires_in)
    last_refresh_dt = datetime.now(timezone.utc)
    return {
        "id_token": token_resp.get("id_token", ""),
        "access_token": token_resp.get("access_token", ""),
        "refresh_token": token_resp.get("refresh_token", ""),
        "account_id": id_claims.get("account_id", ""),
        "last_refresh": last_refresh_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "email": id_claims.get("email", ""),
        "type": "codex",
        "expired": expired_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _timedelta_seconds(seconds: int):
    from datetime import timedelta
    return timedelta(seconds=int(seconds))


def _credential_file_name(email: str, plan_type: str) -> str:
    """Following CLIProxyAPI filename.go: no plan -> codex-{email}.json, otherwise with a plan suffix."""
    email = (email or "").strip()
    plan = (plan_type or "").strip().lower()
    if plan == "":
        return f"codex-{email}.json"
    return f"codex-{email}-{plan}.json"


def save_codex_credential(storage: dict, email: str, plan_type: str) -> str:
    """Save the Codex credential to SQLite, without creating local files."""
    fname = _credential_file_name(email, plan_type)
    db.upsert_codex_credential(storage, fname)
    return f"sqlite://codex_accounts/{fname}"


def _save_codex_credential(email: str, storage: dict) -> str:
    """BrowserUse Compatibility entry point: likewise only saves to SQLite."""
    plan = ""
    if isinstance(storage, dict):
        plan = storage.get("plan_type") or storage.get("chatgpt_plan_type") or ""
    return save_codex_credential(storage, email, plan)


def _extract_cpa_auth_json(payload: dict) -> dict | None:
    """
    Try to extract the complete authorization file from the CPA oauth-callback response.
    Different CPA versions may use different field names; as long as it looks like a codex auth json it is saved locally.
    """
    if not isinstance(payload, dict):
        return None
    candidates = [
        payload.get("auth_json"),
        payload.get("authJson"),
        payload.get("auth"),
        payload.get("auth_file"),
        payload.get("authFile"),
        payload.get("file"),
        payload.get("data"),
    ]
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    candidates.extend([
        data.get("auth_json"),
        data.get("authJson"),
        data.get("auth"),
        data.get("auth_file"),
        data.get("authFile"),
        data.get("file"),
    ])
    for item in candidates:
        if isinstance(item, dict) and (
            item.get("type") == "codex"
            or item.get("access_token")
            or item.get("refresh_token")
            or item.get("id_token")
        ):
            return item
    return None


def _save_cpa_local_record(
    *,
    email: str,
    callback_url: str,
    auth_url: str,
    state: str,
    submit_payload: dict,
) -> str | None:
    """
    Record the CPA authorization result in SQLite:
      1) If CPA returns the complete auth json, save it as a usable codex-email[-plan].json;
      2) otherwise save the callback submission receipt according to the config, to help trace the CPA-side authorization result.
    """
    auth_json = _extract_cpa_auth_json(submit_payload)
    if auth_json:
        effective_email = auth_json.get("email") or email
        plan = auth_json.get("plan_type") or auth_json.get("chatgpt_plan_type") or ""
        return save_codex_credential(auth_json, effective_email, plan)

    if not bool(getattr(_cfg, "CPA_SAVE_CALLBACK_RECEIPT", True)):
        return None

    safe_email = (email or "unknown").strip().replace("/", "_").replace("\\", "_")
    fname = f"codex-{safe_email}-cpa-callback.json"
    record = {
        "type": "codex_cpa_callback",
        "email": email,
        "state": state,
        "auth_url": auth_url,
        "callback_url": callback_url,
        "cpa_management_origin": _cpa_management_origin(),
        "cpa_submit_response": submit_payload,
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "The authorization URL is generated by CPA; the callback has been submitted to CPA. If the CPA response contains no token, this file is a local receipt record.",
    }
    db.upsert_codex_credential(record, fname)
    return f"sqlite://codex_accounts/{fname}"


def _save_sub2_local_record(
    *,
    email: str,
    callback_url: str,
    auth_url: str,
    state: str,
    submit_payload: dict,
) -> str | None:
    """Record the sub2 authorization result in SQLite; if the complete auth json is returned, save it as a Codex credential."""
    auth_json = _extract_cpa_auth_json(submit_payload)
    if auth_json:
        effective_email = auth_json.get("email") or email
        plan = auth_json.get("plan_type") or auth_json.get("chatgpt_plan_type") or ""
        return save_codex_credential(auth_json, effective_email, plan)

    if not bool(getattr(_cfg, "CPA_SAVE_CALLBACK_RECEIPT", True)):
        return None

    safe_email = (email or "unknown").strip().replace("/", "_").replace("\\", "_")
    fname = f"codex-{safe_email}-sub2-callback.json"
    try:
        sub2_origin = _sub2_codex_base()
    except Exception:
        sub2_origin = ""
    record = {
        "type": "codex_sub2_callback",
        "email": email,
        "state": state,
        "auth_url": auth_url,
        "callback_url": callback_url,
        "sub2_origin": sub2_origin,
        "sub2_submit_response": submit_payload,
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "The authorization URL is generated by sub2; the callback has been uploaded to sub2. If the sub2 response contains no token, this file is a local receipt record.",
    }
    db.upsert_codex_credential(record, fname)
    return f"sqlite://codex_accounts/{fname}"


# ============================================================
# Entry point
# ============================================================

def run_codex_oauth(
    email: str,
    otp_provider=None,
    proxy: str | None = None,
    force: bool = False,
    _cpa_reauth_round: int = 1,
) -> dict:
    """
    Codex OAuth authorization entry point after a successful registration (brand new session + SMS code receiving approach).

    The registration session is not reused: a clean BrowserSession is created internally and this email is logged in from scratch,
    going through email OTP -> phone SMS verification -> pick workspace -> get code -> exchange token -> persist.

    Args:
        email: Email of the successfully registered account
        otp_provider: Email OTP retrieval callback fn(email, after_ts)->code, default uses wait_for_otp
        proxy: Proxy (when not passed one is drawn from PROXY_POOL)
        force: True skips the ENABLE_CODEX_AUTO switch limit, for manual reruns

    Returns:
        Structured result dict. Any exception is swallowed and turned into status=failed, never raised upward, and does not affect the registration main flow.
    """
    if not force and not _cfg.ENABLE_CODEX_AUTO:
        return _codex_result(status="skipped", message="ENABLE_CODEX_AUTO=False")
    if not email:
        return _codex_result(status="skipped", message="email is empty")

    # Codex OAuth Supports several drivers:
    # protocol: the original pure protocol; roxy/cloak/browser_use: run the pages in a real browser and capture the localhost callback.
    try:
        from config import codex as _codex_cfg
        from config import roxybrowser as _roxy_cfg
        oauth_driver = str(getattr(_codex_cfg, "CODEX_OAUTH_DRIVER", "protocol") or "protocol").strip().lower()
        if oauth_driver == "same_as_registration":
            oauth_driver = str(getattr(_roxy_cfg, "REGISTRATION_DRIVER", "protocol") or "protocol").strip().lower()
        if oauth_driver in ("roxy", "roxybrowser", "fingerprint", "browser"):
            from core.roxy_codex_oauth import run_roxy_codex_oauth
            return run_roxy_codex_oauth(email, otp_provider=otp_provider, proxy=proxy, force=True)
        if oauth_driver in ("browser_use", "browseruse", "browser-use", "bu"):
            from core.browser_use_codex_oauth import run_browser_use_codex_oauth
            return run_browser_use_codex_oauth(email, otp_provider=otp_provider, proxy=proxy, force=True)
        if oauth_driver in ("skyvern", "sv"):
            from core.skyvern_codex_oauth import run_skyvern_codex_oauth
            return run_skyvern_codex_oauth(email, otp_provider=otp_provider, proxy=proxy, force=True)
        if oauth_driver in ("cloak", "cloakbrowser"):
            from config import cloakbrowser as _cloak_cfg
            from core.cloakbrowser_driver import build_cloak_driver
            from core.roxy_codex_oauth import run_roxy_codex_oauth
            driver, opened = build_cloak_driver(proxy=proxy)
            try:
                return run_roxy_codex_oauth(
                    email,
                    otp_provider=otp_provider,
                    proxy=proxy,
                    force=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    reuse_existing_profile=True,
                    clear_existing_state=True,
                )
            finally:
                if not bool(getattr(_cloak_cfg, "CLOAK_KEEP_BROWSER_OPEN", False)):
                    try:
                        driver.quit()
                    except Exception:
                        pass
        if oauth_driver not in ("protocol", "api", "http"):
            raise RuntimeError(f"[Codex] Unsupported CODEX_OAUTH_DRIVER={oauth_driver!r}, options are protocol / roxy / cloak / browser_use / skyvern")
    except ImportError:
        # Without selenium installed / without a roxy config, the protocol mode is still used, keeping the old behavior.
        pass

    if otp_provider is None:
        from core.email_provider import wait_for_otp as otp_provider

    # One Codex authorization uses a single identity throughout; the next task gets a brand new isolated identity even for the same account.
    task_seed = f"codex-oauth:{email.lower()}:{uuid.uuid4()}"
    session = BrowserSession(proxy=proxy, fingerprint_seed=task_seed)
    try:
        logger.info(f"[Codex] Starting authorization (brand new session):{email}")
        logger.info(
            "[Codex] Unified fingerprint context:device_id=%s oai_session_id=%s auth_session_logging_id=%s %s",
            session.device_id,
            session.oai_session_id,
            session.auth_session_logging_id,
            session.fingerprint_summary_text(),
        )

        # 1. Authorization URL
        #    Generated by CPA by default (PKCE/state are not generated locally); the local mode keeps the old code for compatibility.
        auth_source = _codex_auth_url_source()
        cpa_auth = None
        code_verifier = None
        code_challenge = None
        auth_url = None
        if auth_source == "cpa":
            cpa_auth = _request_cpa_authorize_url()
            state = cpa_auth["state"]
            auth_url = cpa_auth["auth_url"]
            logger.info(f"[Codex] Currently using the CPA authorization URL: {auth_url}")
        elif auth_source == "sub2":
            sub2_auth = _request_sub2_authorize_url()
            state = sub2_auth["state"]
            auth_url = sub2_auth["auth_url"]
            logger.info(f"[Codex] Currently using the sub2 authorization URL: {auth_url}")
        elif auth_source == "local":
            code_verifier, code_challenge = _generate_pkce()
            state = _generate_state()
            logger.info("[Codex] Currently using a locally generated PKCE authorization URL; the full URL will be output in the bootstrap stage")
        else:
            raise RuntimeError(f"[Codex] unsupported CODEX_AUTH_URL_SOURCE={auth_source!r}")

        # 2. Network pre-check + session establishment. The pre-check carries no email and does not trigger an OTP;
        #    the authorize/continue that really burns an email only runs after the pre-check succeeds.
        _codex_protocol_fingerprint_warmup(session)
        human_delay("navigate")
        _codex_auth_preflight(session)
        human_delay("navigate")

        _bootstrap_authorize(session, state, code_challenge, auth_url=auth_url)
        human_delay("navigate")

        # 3. Submit the email. Afterwards the flow is not guessed from "whether the account has a password", but follows what Auth actually returns
        #    page/type/continue_url ; the account password is only a credential to use when a password page appears.
        otp_after_ts = time.time()
        auth_result = _submit_email(session, email)
        human_delay("form")
        login_status, early_callback_url, auth_result = _try_password_mfa_login(
            session, email, state, auth_result
        )
        password_login_done = login_status == "logged_in"

        # 4. Only when Auth explicitly advances the flow to the email verification page is the email OTP polled.
        if not password_login_done and (
            login_status == "email_otp" or _is_email_otp_step(auth_result)
        ):
            email_otp = None
            max_email_otp_attempts = 3
            for email_otp_attempt in range(1, max_email_otp_attempts + 1):
                logger.info(f"[Codex] Waiting for the email OTP: {email} (attempt {email_otp_attempt}/{max_email_otp_attempts})")
                try:
                    email_otp = otp_provider(email, after_ts=otp_after_ts)
                    break
                except Exception as exc:
                    if email_otp_attempt >= max_email_otp_attempts:
                        raise
                    logger.warning(
                        "[Codex] No email OTP received for a long time, resubmitting the email to trigger a resend and continuing to wait (next round %s/%s):%s: %s",
                        email_otp_attempt + 1,
                        max_email_otp_attempts,
                        type(exc).__name__,
                        str(exc)[:180],
                    )
                    otp_after_ts = time.time()
                    auth_result = _submit_email(session, email)
                    human_delay("api")
                    retry_status, retry_callback_url, retry_result = _try_password_mfa_login(
                        session, email, state, auth_result
                    )
                    if retry_status == "logged_in":
                        password_login_done = True
                        early_callback_url = retry_callback_url
                        auth_result = retry_result
                        break
            if not password_login_done:
                logger.info(f"[Codex] Email OTP received:{email_otp}")
                human_delay("otp_input")
                auth_result = _submit_email_otp(session, email_otp)
                human_delay("api")

        # After email verification Auth may still require MFA; the TOTP is only submitted when an MFA state is returned.
        if not password_login_done and _is_mfa_step(
            auth_result, _extract_continue_url(auth_result)
        ):
            auth_result = _complete_mfa_if_required(session, email, auth_result)
            continue_url = _extract_continue_url(auth_result)
            early_callback_url = _follow_login_continue(
                session, continue_url, state
            ) if continue_url else early_callback_url

        # 5. Whether a phone number is needed is also decided entirely by what Auth returns, and is no longer executed as a fixed step just because OTP/password was passed.
        if _is_phone_step(auth_result):
            logger.info("[Codex] Auth Phone verification explicitly required, starting code receiving:%s", email)
            phone_result = _do_phone_verification(session)
            phone_continue = _extract_continue_url(phone_result)
            if phone_continue:
                early_callback_url = _follow_login_continue(
                    session, phone_continue, state
                ) or early_callback_url
                auth_result = phone_result
            human_delay("post_auth")
        else:
            logger.info(
                "[Codex] Auth Phone verification not required, skipping:email=%s page=%s continue=%s",
                email,
                _page_type(auth_result) or "-",
                _extract_continue_url(auth_result) or "-",
            )

        # 6. Pick workspace -> get the callback code; if the login continue already hit the callback directly, reuse it.
        callback_url = early_callback_url or _select_workspace_and_get_callback(session, state)
        code = _extract_code(callback_url, state)
        logger.info(f"[Codex] Got the authorization code:{code[:24]}...")

        # 7A. CPA mode: hand the callback URL to CPA, which holds the verifier and completes the token exchange / writes the auth.
        #     The code is no longer exchanged locally; only the authorization file or callback receipt returned by CPA is saved.
        if auth_source == "cpa":
            submit_payload = _submit_cpa_callback(callback_url)
            path = _save_cpa_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url or "",
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "CPA callback submitted"
            logger.info(f"[Codex][CPA] Success: {email}, {msg}, local record={path or 'disabled'}")
            return _codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=str(msg),
            )

        # 7A-sub2. sub2 mode: upload the callback URL to sub2.
        if auth_source == "sub2":
            submit_payload = _submit_sub2_callback(
                callback_url,
                session_id=(sub2_auth or {}).get("session_id", ""),
                redirect_uri=(parse_qs(urlparse(auth_url or "").query).get("redirect_uri") or [""])[0],
            )
            path = _save_sub2_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url or "",
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "sub2 callback uploaded"
            logger.info(f"[Codex][sub2] Success: {email}, {msg}, local record={path or 'disabled'}")
            return _codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=str(msg),
            )

        # 7B. local mode: keep the old implementation, exchange the token with the local verifier and save a CPA-compatible authorization file.
        if not code_verifier:
            raise RuntimeError("[Codex] local mode is missing code_verifier")
        token_resp = exchange_codex_token(session, code, code_verifier)

        # 8. Parse the id_token + persist
        id_claims = _parse_id_token(token_resp.get("id_token", ""))
        effective_email = id_claims.get("email") or email
        storage = build_codex_storage(token_resp, id_claims)
        path = save_codex_credential(storage, effective_email, id_claims.get("plan_type", ""))

        logger.info(
            f"[Codex] Success: {effective_email},plan={id_claims.get('plan_type') or 'unknown'}, "
            f"account_id={id_claims.get('account_id') or 'unknown'}, saved to {path}"
        )
        return _codex_result(
            status="success",
            ok=True,
            email=effective_email,
            file_path=str(path),
            callback_url=callback_url,
            message=f"plan={id_claims.get('plan_type') or 'unknown'}",
        )
    except AccountUnusableError as exc:
        logger.warning(f"[Codex] Account is dead ({exc.error_code}):{email}")
        return _codex_result(
            status="deactivated",
            email=email,
            message=f"Account is dead ({exc.error_code})",
        )
    except Exception as exc:
        if _is_cpa_callback_reauth_error(exc) and _cpa_reauth_round < 2:
            logger.warning(
                "[Codex][CPA] callback returned Timeout waiting for OAuth callback, starting Codex authorization round %s/2 again:%s",
                _cpa_reauth_round + 1, email,
            )
            return run_codex_oauth(
                email,
                otp_provider=otp_provider,
                proxy=proxy,
                force=force,
                _cpa_reauth_round=_cpa_reauth_round + 1,
            )
        logger.warning(f"[Codex] Failed: {email},{type(exc).__name__}: {str(exc)[:200]}")
        logger.debug("[Codex] failure details:", exc_info=True)
        return _codex_result(
            status="failed",
            email=email,
            message=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
