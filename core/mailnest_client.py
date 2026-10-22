# -*- coding: utf-8 -*-
"""MailNest/Maichao temporary email client."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp, looks_like_openai_email

logger = logging.getLogger(__name__)

BASE_URL = "https://mailnest.top"
REQUEST_TIMEOUT = 20


class MailNestClientError(RuntimeError):
    """MailNest email service related exceptions."""


@dataclass
class MailNestAccount:
    email: str
    project_code: str = ""


_CONTEXT_CACHE: dict[str, MailNestAccount] = {}


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _api_key() -> str:
    api_key = str(getattr(_email_cfg, "MAIL_NEST_API_KEY", "") or "").strip()
    if not api_key:
        raise MailNestClientError("MailNest API Key is not configured, please enter the MailNest API Key (WebUI: Config > Email / OTP).")
    return api_key


def _project_code() -> str:
    project_code = str(getattr(_email_cfg, "MAIL_NEST_PROJECT_CODE", "") or "").strip()
    if not project_code:
        raise MailNestClientError("MailNest project code is not configured, please enter the MailNest project code (default chatgpt001).")
    return project_code


def _request(method: str, path: str, *, params: dict | None = None, json: dict | None = None):
    try:
        resp = requests.request(
            method,
            BASE_URL + path,
            params=params,
            json=json,
            headers={"Authorization": f"Bearer {_api_key()}", "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise MailNestClientError(f"MailNest Request failed ({path}): {type(exc).__name__}: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError as exc:
        raise MailNestClientError(f"MailNest response is not JSON ({path}): HTTP {resp.status_code}") from exc

    if resp.status_code == 401:
        raise MailNestClientError("MailNest API Key is invalid or expired")
    if resp.status_code >= 400:
        raise MailNestClientError(f"MailNest Request failed ({path}): HTTP {resp.status_code}; {str(payload)[:200]}")
    if not isinstance(payload, dict) or str(payload.get("code")) != "00000":
        raise MailNestClientError(f"MailNest Request failed ({path}): {payload}")
    return payload.get("data")


def pick_account() -> MailNestAccount:
    """Purchase/claim a MailNest temporary email and cache its context."""
    project_code = _project_code()
    data = _request(
        "POST",
        "/api/v1/email/temporary/buy",
        json={"project_code": project_code, "count": 1},
    )
    if not isinstance(data, list) or not data:
        raise MailNestClientError("MailNest purchase email response is missing data[0]")
    email = str((data[0] or {}).get("email") or "").strip()
    if not email or "@" not in email:
        raise MailNestClientError("MailNest purchase email response is missing a valid email")
    account = MailNestAccount(email=email, project_code=project_code)
    _CONTEXT_CACHE[_cache_key(email)] = account
    logger.info("[MailNest] Temporary email acquired: %s project_code=%s", email, project_code)
    return account


def get_email() -> str:
    """Compatible with the old entry point: return the newly claimed email address."""
    return pick_account().email


def get_account_context(email: str) -> MailNestAccount | None:
    return _CONTEXT_CACHE.get(_cache_key(email))


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    _CONTEXT_CACHE.pop(_cache_key(email), None)
    logger.info("[MailNest] Released temporary email: %s (status=%s, note=%s)", email, status, note or "")


def _get_mails(email: str):
    return _request("POST", "/api/v1/email/receive", json={"email": email})


def _timestamp(item: dict) -> float | None:
    for key in ("timestamp", "created_at", "create_time", "received_at", "date"):
        raw = item.get(key)
        if raw is None or raw == "":
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            pass
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return None


def _otp_item(item: dict) -> dict:
    return {
        "id": item.get("id") or item.get("mail_id"),
        "from": item.get("from") or item.get("from_address") or item.get("sender") or "",
        "subject": item.get("subject") or item.get("title") or "",
        "text": item.get("text") or item.get("content") or item.get("body") or "",
        "html": item.get("html") or item.get("html_content") or "",
    }


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """Poll MailNest and return the latest OpenAI six-digit verification code after the claim time."""
    target = str(email or "").strip()
    if not target:
        raise MailNestClientError("MailNest code retrieval is missing the email address")

    wait_seconds = int(max_wait if max_wait is not None else _email_cfg.OTP_MAX_WAIT)
    interval = max(1, int(poll_interval if poll_interval is not None else _email_cfg.OTP_POLL_INTERVAL))
    settle = max(0, int(settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS))
    deadline = time.monotonic() + max(0, wait_seconds)
    best_otp: str | None = None
    best_timestamp = float("-inf")
    settle_until: float | None = None
    last_error = "Inbox is empty or no new OpenAI verification code has appeared yet"

    logger.info("[MailNest] Start polling email %s, for at most %ss", target, wait_seconds)
    while time.monotonic() <= deadline:
        try:
            mails = _get_mails(target)
            if not isinstance(mails, list):
                raise MailNestClientError("MailNest inbox response is not an array")
            for mail in sorted(mails, key=lambda item: _timestamp(item) or float("-inf"), reverse=True):
                if not isinstance(mail, dict):
                    continue
                message_time = _timestamp(mail)
                if after_ts is not None and message_time is not None and message_time < after_ts - 30:
                    continue

                otp = str(mail.get("code_match") or "").strip()
                item = _otp_item(mail)
                if not otp:
                    if not looks_like_openai_email(item):
                        continue
                    otp = extract_otp(item) or ""
                if not otp:
                    continue

                candidate_time = float("-inf") if message_time is None else message_time
                if best_otp is None or candidate_time > best_timestamp or (candidate_time == best_timestamp and otp != best_otp):
                    best_otp = otp
                    best_timestamp = candidate_time
                    settle_until = time.monotonic() + settle
                    logger.info("[MailNest] Locked OTP candidate, waiting %ss for confirmation", settle)

            now = time.monotonic()
            if best_otp and settle_until is not None and now >= settle_until:
                return best_otp
        except MailNestClientError as exc:
            last_error = str(exc)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    if best_otp:
        return best_otp
    raise MailNestClientError(f"Timed out waiting for MailNest verification code: {target}; {last_error}")
