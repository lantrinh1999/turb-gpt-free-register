# -*- coding: utf-8 -*-
"""
ChatGPT Auth module
Handle authentication requests under the chatgpt.com domain (steps 1-3)
"""
import json
import logging
from urllib.parse import urlencode, urlparse, parse_qs

from core.session import BrowserSession
from config import (
    OPENAI_CLIENT_ID, OPENAI_SCOPE, OPENAI_AUDIENCE, OPENAI_REDIRECT_URI
)

logger = logging.getLogger(__name__)

# 2026-09-14 Roxy Successful sample: signin no longer actively carries passkey capabilities;
# authorize uses two ccaps and explicitly returns to the ChatGPT home page.
_CC_CAPS = "login_methods chatgpt_login_finalizer_v1"


def _ensure_authorize_context(authorize_url: str, session: BrowserSession, email: str) -> str:
    """
    Final fallback for the authorize URL returned by NextAuth: ensure the current frontend default
    login_or_signup flow context parameters are not lost during redirect generation.
    """
    try:
        parsed = urlparse(authorize_url)
        if not parsed.netloc.endswith("auth.openai.com"):
            return authorize_url
        params = parse_qs(parsed.query, keep_blank_values=True)
        # The old implementation actively injected this field; the currently successful browser authorize no longer carries it.
        changed = bool(params.pop("ext-passkey-client-capabilities", None))
        language_getter = getattr(session, "navigator_language", None)
        if callable(language_getter):
            ui_locale = str(language_getter() or "en-US")
        else:
            # Compatible with slim sessions/old task objects, while avoiding silently dropping
            # ext-oai-did the entire authorize context just because a helper method is missing.
            profile = getattr(session, "browser_profile", {}) or {}
            ui_locale = str(profile.get("navigator_language") or "en-US")
        required = {
            "ext-oai-did": session.device_id,
            "auth_session_logging_id": session.auth_session_logging_id,
            "screen_hint": "login_or_signup",
            "login_hint": email,
            "ui_locales": ui_locale,
            "ccaps": _CC_CAPS,
            "auth_return_target_category": "chatgpt_home",
        }
        for key, value in required.items():
            if key in {"ccaps", "auth_return_target_category", "ui_locales"}:
                if params.get(key) != [value]:
                    params[key] = [value]
                    changed = True
            elif not params.get(key):
                params[key] = [value]
                changed = True
        if not changed:
            return authorize_url
        logger.info(
            "[Step 3] authorize context aligned: ui_locales=%s oai-did=%s",
            ui_locale,
            str(session.device_id)[:12] + "...",
        )
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
    except Exception:
        return authorize_url


def get_providers(session: BrowserSession) -> dict:
    """
    Step 1: Get the OAuth Providers list.
    GET https://chatgpt.com/api/auth/providers

    Verify the connection to chatgpt.com works and get the available OAuth providers.

    Returns:
        providers dict, for example:
        {
            "openai": {
                "id": "openai",
                "name": "openai",
                "type": "oauth",
                "signinUrl": "https://chatgpt.com/api/auth/signin/openai",
                "callbackUrl": "https://chatgpt.com/api/auth/callback/openai"
            },
            ...
        }
    """
    url = "https://chatgpt.com/api/auth/providers"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")

    logger.info("[Step 1] Fetching OAuth Providers...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    logger.info(f"[Step 1] Successfully fetched {len(data)} providers: {list(data.keys())}")
    return data


def get_csrf_token(session: BrowserSession) -> str:
    """
    Step 2: Get the CSRF Token.
    GET https://chatgpt.com/api/auth/csrf

    CSRF token will be used in the subsequent signin request.

    Returns:
        csrfToken string
    """
    url = "https://chatgpt.com/api/auth/csrf"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")

    logger.info("[Step 2] Fetching CSRF Token...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    csrf_token = data.get("csrfToken", "")
    logger.info(f"[Step 2] CSRF Token fetched successfully: {csrf_token[:20]}...")
    return csrf_token


def probe_auth_session(session: BrowserSession) -> dict:
    """Read an anonymous NextAuth session once after providers, following the order of the Web login page."""
    url = "https://chatgpt.com/api/auth/session"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")
    logger.info("[Step 1.5] Reading anonymous Auth Session...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        data = {}
    return data if isinstance(data, dict) else {}


def signin_openai(session: BrowserSession, csrf_token: str, email: str) -> str:
    """
    Step 3: Initiate the OAuth Signin request.
    POST https://chatgpt.com/api/auth/signin/openai

    Build the OAuth authorization parameters and get the authorize URL.

    Args:
        session: browser session
        csrf_token: from step 2, the CSRF token
        email: registration email

    Returns:
        authorize_url: auth.openai.com authorization URL
    """
    # Build URL query parameters
    query_params = {
        "prompt": "login",
        "ext-oai-did": session.device_id,
        "auth_session_logging_id": session.auth_session_logging_id,
        "screen_hint": "login_or_signup",
        "login_hint": email,
    }
    url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query_params)

    # Build request headers
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    # Build request body
    body = urlencode({
        "callbackUrl": "/",
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info(f"[Step 3] Initiating OAuth Signin request, email: {email}")
    resp = session.post(url, headers=headers, data=body)
    resp.raise_for_status()

    data = resp.json()
    authorize_url = data.get("url", "")

    if not authorize_url:
        raise ValueError(f"[Step 3] Failed to get authorize URL, response: {data}")

    authorize_url = _ensure_authorize_context(authorize_url, session, email)
    logger.info("[Step 3] Got authorize URL successfully, login_or_signup/oai-did context confirmed")
    logger.debug(f"[Step 3] URL: {authorize_url[:160]}...")
    return authorize_url
