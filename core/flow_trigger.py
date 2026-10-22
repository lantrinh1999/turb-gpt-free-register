# -*- coding: utf-8 -*-
"""
Module that automatically triggers the "flow" after successful registration.

The main flow calls this after obtaining access_token in main.py / registration_service.py:
    trigger_flow(access_token)
Regardless of whether the trigger succeeds, the main registration flow is considered successful.
"""
import json
import logging

# This is an internal HTTP endpoint (156.225.31.95) with no Cloudflare interception,
# so curl_cffi TLS fingerprint emulation is not needed; use the standard requests library directly.
import requests

# Read config via module attributes to support WebUI hot reload (config.reload_all()).
from config import flow_trigger as _cfg
from config.browser import USER_AGENT, ACCEPT_LANGUAGE  # Browser fingerprint is fixed, no hot reload needed

logger = logging.getLogger(__name__)


def _flow_result(
    *,
    status: str,
    ok: bool = False,
    http_status: int | None = None,
    flow_id: str | None = None,
    message: str = "",
) -> dict:
    return {
        "status": status,
        "ok": ok,
        "http_status": http_status,
        "flow_id": flow_id,
        "message": message,
    }


def _build_headers() -> dict:
    return {
        "Accept": "*/*",
        "Accept-Language": ACCEPT_LANGUAGE,
        "Authorization": f"Bearer {_cfg.FLOW_TRIGGER_BEARER}",
        "Cache-Control": "no-cache",
        "Content-Type": "application/json",
        "Origin": "http://162.211.183.196:8888",
        "Pragma": "no-cache",
        "Referer": "http://162.211.183.196:8888/",
        "User-Agent": USER_AGENT,
        "Cookie": _cfg.FLOW_TRIGGER_COOKIE,
    }


def _send_sync(access_token: str) -> dict:
    """Actually execute the HTTP POST synchronously and return a result suitable for statistics."""
    if not access_token:
        return _flow_result(status="skipped", message="access_token is empty")

    body = dict(_cfg.FLOW_TRIGGER_PAYLOAD)
    body["access_token"] = access_token

    try:
        resp = requests.post(
            _cfg.FLOW_TRIGGER_URL,
            headers=_build_headers(),
            json=body,
            timeout=_cfg.FLOW_TRIGGER_TIMEOUT,
            verify=False,
        )
    except Exception as exc:
        return _flow_result(status="failed", message=f"{type(exc).__name__}: {exc}")

    # Simply parse flow_id for logging; the trigger result does not affect the main flow
    flow_id = ""
    response_preview = (resp.text or "")[:200]
    try:
        data = resp.json()
        flow_id = (data.get("flow") or {}).get("flow_id", "")
    except Exception:
        pass

    if resp.status_code == 200:
        return _flow_result(
            status="success",
            ok=True,
            http_status=resp.status_code,
            flow_id=flow_id or None,
            message=response_preview,
        )

    return _flow_result(
        status="failed",
        http_status=resp.status_code,
        flow_id=flow_id or None,
        message=response_preview,
    )


def trigger_flow(access_token: str) -> dict:
    """
    Trigger the 156.225 flow endpoint and return the result.

    Args:
        access_token: From this registration, the ChatGPT access_token
    """
    if not _cfg.ENABLE_FLOW_TRIGGER:
        return _flow_result(status="skipped", message="ENABLE_FLOW_TRIGGER=False")

    if not access_token:
        return _flow_result(status="skipped", message="access_token is empty")

    return _send_sync(access_token)
