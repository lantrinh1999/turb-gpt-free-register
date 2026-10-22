# -*- coding: utf-8 -*-
"""WebUI authorization code login and API authentication."""
from __future__ import annotations

import hmac
import hashlib
import logging
import os
import secrets
from datetime import timedelta
from typing import Any

from flask import Response, jsonify, redirect, render_template, request, session, url_for

logger = logging.getLogger(__name__)

AUTH_ENV_KEYS = ("WEBUI_AUTH_CODE", "AUTH_CODE", "WEB_AUTH_CODE")
_SESSION_KEY = "webui_auth_ok"
_AUTH_CODE: str | None = None
_GENERATED = False

def init_auth(app: Any, *, auth_code: str | None = None) -> str:
    """Initialize the authorization code and Flask session. Generate a temporary authorization code when not explicitly configured."""
    global _AUTH_CODE, _GENERATED

    code = (auth_code or "").strip()
    if not code:
        try:
            from config.env_loader import load_env, env_str
            load_env(override=False)
            for key in AUTH_ENV_KEYS:
                code = env_str(key, "")
                if code:
                    break
        except Exception:
            for key in AUTH_ENV_KEYS:
                code = (os.getenv(key) or "").strip()
                if code:
                    break

    if not code:
        code = secrets.token_urlsafe(18)
        _GENERATED = True
    else:
        _GENERATED = False

    _AUTH_CODE = code
    session_secret = os.getenv("WEBUI_SESSION_SECRET") or os.getenv("FLASK_SECRET_KEY")
    if not session_secret:
        # When the authorization code comes from .env, a namespaced digest is used to derive a stable signing key; changing the authorization code naturally logs out old sessions.
        session_secret = hashlib.sha256(f"turb-gpt-webui-session:{code}".encode("utf-8")).hexdigest()
    app.secret_key = session_secret
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    )
    return code


def is_generated_code() -> bool:
    return _GENERATED


def expected_auth_code() -> str:
    return _AUTH_CODE or ""


def _extract_auth_code() -> str:
    # Non-login endpoints accept only the Header authorization code, so that authorization codes in query/body do not end up in logs, Referer or business data.
    header_code = (request.headers.get("X-Auth-Code") or request.headers.get("X-Authorization-Code") or "").strip()
    if header_code:
        return header_code
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def code_is_valid(code: str) -> bool:
    expected = expected_auth_code()
    return bool(expected) and bool(code) and hmac.compare_digest(str(code), expected)


def request_is_authorized() -> bool:
    if session.get(_SESSION_KEY) is True:
        return True
    return code_is_valid(_extract_auth_code())


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.headers.get("Accept") or ""
    return "application/json" in accept and "text/html" not in accept


def _unauthorized_response():
    if _wants_json():
        return jsonify({"ok": False, "error": "Unauthorized: please log in or provide the authorization code"}), 401
    return redirect(url_for("auth_login", next=request.path))


def register_auth_routes(app: Any) -> None:
    @app.before_request
    def _require_auth_code():
        endpoint = request.endpoint or ""
        if endpoint in {"auth_login", "auth_logout", "static"}:
            return None
        if request.path in ("/favicon.ico",):
            return Response(status=204)
        if request_is_authorized():
            return None
        return _unauthorized_response()

    @app.route("/login", methods=["GET", "POST"], endpoint="auth_login")
    def _auth_login():
        error = ""
        next_url = request.values.get("next") or "/"
        if not str(next_url).startswith("/") or str(next_url).startswith("//"):
            next_url = "/"
        if request.method == "POST":
            code = (request.form.get("auth_code") or "").strip()
            remember = (request.form.get("remember") or "").strip().lower() in ("1", "true", "on", "yes")
            if code_is_valid(code):
                session.permanent = remember
                session[_SESSION_KEY] = True
                return redirect(next_url)
            error = "Incorrect authorization code"
        return render_template("login.html", error=error, next_url=next_url, login_url=url_for("auth_login"))

    @app.post("/logout", endpoint="auth_logout")
    def _auth_logout():
        session.pop(_SESSION_KEY, None)
        if _wants_json():
            return jsonify({"ok": True})
        return redirect(url_for("auth_login"))
