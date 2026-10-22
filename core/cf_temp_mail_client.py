# -*- coding: utf-8 -*-
"""Cloudflare Worker Temporary email client (cloudflare_temp_email compatible).

Aligned with grokRegister-cpa/email_providers/cloudflare.py:
  - POST new_address / admin/new_address auto-create the email and obtain the jwt
  - GET mails poll the inbox and extract the OpenAI six-digit OTP
"""
from __future__ import annotations

import logging
import re
import secrets
import string
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from typing import Any

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp, looks_like_openai_email

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 20
_DOMAIN_COUNTER = 0
_DOMAIN_LOCK = threading.Lock()


class CFTempMailError(RuntimeError):
    """Cloudflare Worker Temporary email request or code retrieval failed."""


@dataclass
class CFTempMailAccount:
    email: str
    jwt: str
    domain: str = ""
    created_at: float = 0.0


_CONTEXT_CACHE: dict[str, CFTempMailAccount] = {}


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _cfg_str(name: str, default: str = "") -> str:
    return str(getattr(_email_cfg, name, default) or default).strip()


def _cfg_int(name: str, default: int) -> int:
    try:
        return int(getattr(_email_cfg, name, default) or default)
    except (TypeError, ValueError):
        return default


def _normalize_path(path: str, default: str) -> str:
    raw = str(path or default or "").strip() or default
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def _base_url() -> str:
    base = _cfg_str("CLOUDFLARE_API_BASE")
    if not base:
        raise CFTempMailError(
            "Cloudflare API address is not configured, fill in CLOUDFLARE_API_BASE (WebUI Settings, Email / OTP section)."
        )
    if not re.match(r"^https?://", base, re.I):
        base = "https://" + base
    return base.rstrip("/")


def _timeout() -> int:
    return max(5, _cfg_int("CLOUDFLARE_REQUEST_TIMEOUT", DEFAULT_TIMEOUT))


def _auth_mode() -> str:
    return _cfg_str("CLOUDFLARE_AUTH_MODE", "none").lower() or "none"


def _api_key() -> str:
    return _cfg_str("CLOUDFLARE_API_KEY")


def _custom_auth() -> str:
    return _cfg_str("CLOUDFLARE_CUSTOM_AUTH")


def _apply_custom_auth(headers: dict[str, str]) -> dict[str, str]:
    custom = _custom_auth()
    if custom:
        headers["x-custom-auth"] = custom
    return headers


def _build_headers(*, content_type: bool = False, bearer_jwt: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = "application/json"
    if bearer_jwt:
        headers["Authorization"] = f"Bearer {bearer_jwt}"
    else:
        key = _api_key()
        mode = _auth_mode()
        if key:
            if mode == "x-api-key":
                headers["X-API-Key"] = key
            elif mode == "x-admin-auth":
                headers["x-admin-auth"] = key
            elif mode == "bearer":
                headers["Authorization"] = f"Bearer {key}"
            elif mode not in ("none", "query-key"):
                headers["Authorization"] = f"Bearer {key}"
    return _apply_custom_auth(headers)


def _auth_params(params: dict | None = None) -> dict:
    merged = dict(params or {})
    key = _api_key()
    if key and _auth_mode() == "query-key":
        merged["key"] = key
    return merged


def _is_admin_create_path(path: str) -> bool:
    return str(path or "").rstrip("/").lower().endswith("/admin/new_address")


def _normalize_domains(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = raw.replace(";", "\n").replace(",", "\n").splitlines()
    else:
        try:
            parts = list(raw)
        except TypeError:
            parts = [raw]
    out: list[str] = []
    for item in parts:
        domain = str(item or "").strip().lower().lstrip("@")
        if domain and "." in domain and " " not in domain and domain not in out:
            out.append(domain)
    return out


def _default_domains() -> list[str]:
    return _normalize_domains(getattr(_email_cfg, "CLOUDFLARE_DEFAULT_DOMAINS", []) or [])


def _next_domain() -> str:
    domains = _default_domains()
    if not domains:
        return ""
    global _DOMAIN_COUNTER
    with _DOMAIN_LOCK:
        domain = domains[_DOMAIN_COUNTER % len(domains)]
        _DOMAIN_COUNTER += 1
    return domain


def _generate_local(length: int | None = None) -> str:
    n = max(3, int(length if length is not None else _cfg_int("CLOUDFLARE_NAME_LENGTH", 10)))
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _request(
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
    params: dict | None = None,
    bearer_jwt: str | None = None,
    content_type: bool = False,
) -> Any:
    url = _base_url() + _normalize_path(path, path or "/")
    headers = _build_headers(content_type=content_type or json_body is not None, bearer_jwt=bearer_jwt)
    query = _auth_params(params)
    try:
        response = requests.request(
            method.upper(),
            url,
            headers=headers,
            json=json_body,
            params=query or None,
            timeout=_timeout(),
        )
    except requests.RequestException as exc:
        raise CFTempMailError(f"Cloudflare Request failed ({path}): {type(exc).__name__}: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        text = (getattr(response, "text", "") or "")[:200]
        if response.status_code >= 400:
            raise CFTempMailError(
                f"Cloudflare Request failed ({path}): HTTP {response.status_code}; {text}"
            ) from exc
        raise CFTempMailError(
            f"Cloudflare response is not JSON ({path}): HTTP {response.status_code}; {text}"
        ) from exc

    if response.status_code >= 400:
        message = ""
        if isinstance(payload, dict):
            message = str(payload.get("message") or payload.get("error") or payload.get("msg") or "")
        if not message:
            message = str(payload)[:200]
        hint = ""
        if response.status_code in (401, 403) and "turnstile" in message.lower():
            hint = "; anonymous creation may be blocked by Turnstile, switch to x-admin-auth + /admin/new_address"
        elif response.status_code in (401, 403) and _auth_mode() == "none":
            hint = "; try CLOUDFLARE_AUTH_MODE=x-admin-auth and fill in ADMIN_PASSWORD"
        raise CFTempMailError(
            f"Cloudflare Request failed ({path}): HTTP {response.status_code}; {message}{hint}"
        )
    return payload


def _pick_list_payload(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("results", "hydra:member", "data", "messages", "mails", "emails"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            for nested_key in ("messages", "mails", "emails", "results", "list"):
                nested = value.get(nested_key)
                if isinstance(nested, list):
                    return [item for item in nested if isinstance(item, dict)]
    return []


def create_address(domain: str | None = None) -> CFTempMailAccount:
    """Call the Worker to create a temporary email, returning address + jwt."""
    accounts_path = _normalize_path(
        _cfg_str("CLOUDFLARE_PATH_ACCOUNTS", "/api/new_address"),
        "/api/new_address",
    )
    selected_domain = str(domain or "").strip().lstrip("@") or _next_domain()
    mode = _auth_mode()
    key = _api_key()
    admin_create = _is_admin_create_path(accounts_path)

    if admin_create or mode in ("x-admin-auth", "bearer", "x-api-key", "query-key"):
        if not key:
            raise CFTempMailError(
                "Cloudflare admin/The auth mode requires CLOUDFLARE_API_KEY (ADMIN_PASSWORD)."
            )

    if admin_create:
        payload: dict[str, Any] = {
            "name": _generate_local(),
            "enablePrefix": True,
        }
        if selected_domain:
            payload["domain"] = selected_domain
    else:
        # Anonymous /api/new_address: domain only; auth headers are still injected per AUTH_MODE (if a Key is configured)
        payload = {}
        if selected_domain:
            payload["domain"] = selected_domain

    data = _request("POST", accounts_path, json_body=payload, content_type=True)
    if not isinstance(data, dict):
        raise CFTempMailError(f"Cloudflare malformed create-email response: {str(data)[:200]}")

    nested = data.get("data") if isinstance(data.get("data"), dict) else {}
    address = str(data.get("address") or nested.get("address") or nested.get("email") or data.get("email") or "").strip()
    jwt = str(data.get("jwt") or nested.get("jwt") or nested.get("token") or data.get("token") or "").strip()
    if not address or "@" not in address:
        raise CFTempMailError(f"Cloudflare create-email response is missing address: {str(data)[:200]}")
    if not jwt:
        raise CFTempMailError(f"Cloudflare create-email response is missing jwt: {str(data)[:200]}")

    domain_part = address.split("@", 1)[-1].lower()
    account = CFTempMailAccount(
        email=address,
        jwt=jwt,
        domain=domain_part,
        created_at=time.time(),
    )
    logger.info("[Cloudflare] Created temporary email: %s (domain=%s)", address, domain_part)
    return account


def pick_account() -> CFTempMailAccount:
    """Create and cache a Cloudflare temporary email."""
    account = create_address()
    _CONTEXT_CACHE[_cache_key(account.email)] = account
    return account


def get_account_context(email: str) -> CFTempMailAccount | None:
    return _CONTEXT_CACHE.get(_cache_key(email))


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    _CONTEXT_CACHE.pop(_cache_key(email), None)
    logger.info(
        "[Cloudflare] Released temporary email: %s (status=%s, note=%s)",
        email,
        status,
        note or "",
    )


def _message_timestamp(item: dict) -> float | None:
    """Parse the email time. The Worker created_at is mostly UTC without a timezone suffix, so it must be interpreted as UTC."""
    for key in ("timestamp", "created_at", "createdAt", "date", "receivedAt", "time"):
        raw = item.get(key)
        if raw is None or raw == "":
            continue
        if isinstance(raw, (int, float)):
            value = float(raw)
            if value > 1e12:
                value = value / 1000.0
            return value
        text = str(raw).strip()
        if not text:
            continue
        try:
            if text.isdigit():
                value = float(text)
                if value > 1e12:
                    value /= 1000.0
                return value
            # Supports "2026-07-19 12:57:38" / ISO
            normalized = text.replace("Z", "+00:00")
            if "T" not in normalized and " " in normalized and "+" not in normalized[10:]:
                # Space-separated time without timezone: treat as UTC (common in cloudflare_temp_email)
                dt = datetime.fromisoformat(normalized).replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(normalized)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
        try:
            dt = parsedate_to_datetime(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            continue
    return None


def _strip_html(value: str) -> str:
    return re.sub(r"<[^>]+>", " ", value or "")


def _message_text(item: dict) -> str:
    parts: list[str] = []
    for field in ("text", "raw", "content", "intro", "body", "snippet", "bodyText", "bodyPreview"):
        value = item.get(field)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    html = item.get("html") or item.get("html_content") or item.get("bodyHtml")
    if isinstance(html, str) and html.strip():
        parts.append(_strip_html(html))
    elif isinstance(html, list):
        for chunk in html:
            if isinstance(chunk, str) and chunk.strip():
                parts.append(_strip_html(chunk))
    return "\n".join(parts)


def _message_addresses(item: dict) -> list[str]:
    out: list[str] = []
    for key in ("address", "to", "recipient", "recipients"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip().lower())
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, str) and entry.strip():
                    out.append(entry.strip().lower())
                elif isinstance(entry, dict):
                    addr = entry.get("address") or entry.get("email") or entry.get("addr")
                    if addr:
                        out.append(str(addr).strip().lower())
    return out


def _decode_mime_header(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    out: list[str] = []
    for part, charset in parts:
        if isinstance(part, bytes):
            out.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            out.append(str(part))
    return "".join(out).strip()


def _parse_raw_email(raw: str) -> dict[str, str]:
    """Parse the raw MIME of cloudflare_temp_email into subject/from/text/html."""
    result = {"subject": "", "from": "", "text": "", "html": ""}
    if not (raw or "").strip():
        return result
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8", errors="replace"))
    except Exception:
        # Fallback: at least extract from the header Subject/From
        for line in raw.splitlines():
            low = line.lower()
            if low.startswith("subject:") and not result["subject"]:
                result["subject"] = _decode_mime_header(line.split(":", 1)[1].strip())
            elif low.startswith("from:") and not result["from"]:
                result["from"] = line.split(":", 1)[1].strip()
        result["text"] = raw
        return result

    result["subject"] = _decode_mime_header(str(msg.get("subject") or ""))
    result["from"] = str(msg.get("from") or "").strip()
    texts: list[str] = []
    htmls: list[str] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace")
        if not isinstance(body, str):
            body = str(body)
        if ctype == "text/plain":
            texts.append(body)
        else:
            htmls.append(body)
    result["text"] = "\n".join(texts).strip()
    result["html"] = "\n".join(htmls).strip()
    if not result["text"] and not result["html"]:
        result["text"] = raw
    return result


def _standalone_otp_from_html(html: str) -> str | None:
    """OpenAI emails commonly have the code alone on its own line/cell, e.g. >449759<."""
    if not html:
        return None
    # Strip style to reduce false hits from colors like #353740
    cleaned = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.I | re.S)
    for pattern in (
        r">\s*(\d{6})\s*<",
        r"(?m)^\s*(\d{6})\s*$",
    ):
        matches = re.findall(pattern, cleaned)
        # Filtering obvious color/tracking-number contexts is done at the upper layer; taking the last standalone code here is closer to the body text OTP
        if matches:
            return matches[-1]
    return None


def _otp_item(item: dict) -> dict:
    raw = item.get("raw") if isinstance(item.get("raw"), str) else ""
    parsed = _parse_raw_email(raw) if raw else {"subject": "", "from": "", "text": "", "html": ""}

    sender = (
        item.get("from")
        or item.get("from_address")
        or item.get("sender")
        or item.get("source")  # cloudflare_temp_email list fields
        or parsed.get("from")
        or ""
    )
    subject = item.get("subject") or parsed.get("subject") or ""
    text = item.get("text") or parsed.get("text") or ""
    html = item.get("html") if isinstance(item.get("html"), str) else ""
    if not html:
        html = parsed.get("html") or ""

    # If only raw exists and MIME parsing fails, keep the non-header text as a fallback
    if not text and not html and raw:
        text = raw

    # Put the standalone 6-digit code at the start of text first, so extract_otp hits the body OTP rather than email header noise
    standalone = _standalone_otp_from_html(html) or _standalone_otp_from_html(text)
    if standalone:
        text = f"verification code {standalone}\n{text}"

    return {
        "id": item.get("id") or item.get("msgid") or item.get("mail_id"),
        "from": sender,
        "subject": subject,
        "text": text,
        "html": html,
        "to": ", ".join(_message_addresses(item)),
    }


def _message_id(item: dict) -> str:
    return str(item.get("id") or item.get("msgid") or item.get("mail_id") or "").strip()


def list_messages(jwt: str, *, limit: int = 20, offset: int = 0) -> list[dict]:
    """Fetch the inbox. /api/mails of cloudflare_temp_email requires a valid limit (otherwise HTTP 400 Invalid limit)."""
    path = _normalize_path(
        _cfg_str("CLOUDFLARE_PATH_MESSAGES", "/api/mails"),
        "/api/mails",
    )
    # Aligned with grokRegister-cpa: limit/offset are required query parameters
    safe_limit = max(1, min(100, int(limit or 20)))
    safe_offset = max(0, int(offset or 0))
    payload = _request(
        "GET",
        path,
        bearer_jwt=jwt,
        params={"limit": safe_limit, "offset": safe_offset},
    )
    return _pick_list_payload(payload)


def get_message_detail(jwt: str, message_id: str) -> dict:
    if not message_id:
        return {}
    messages_path = _normalize_path(
        _cfg_str("CLOUDFLARE_PATH_MESSAGES", "/api/mails"),
        "/api/mails",
    )
    candidates = [
        f"/api/mail/{message_id}",
        f"{messages_path}/{message_id}",
    ]
    last_error: Exception | None = None
    for path in candidates:
        try:
            payload = _request("GET", path, bearer_jwt=jwt)
            if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
                return payload["data"]
            if isinstance(payload, dict):
                return payload
        except CFTempMailError as exc:
            last_error = exc
            continue
    if last_error:
        logger.debug("[Cloudflare] Failed to fetch email details id=%s: %s", message_id, last_error)
    return {}


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """Poll the Cloudflare mailbox and return the latest OpenAI six-digit verification code received after the claim time."""
    target = str(email or "").strip()
    if not target:
        raise CFTempMailError("Cloudflare code retrieval is missing the email address")

    account = get_account_context(target)
    if account is None or not account.jwt:
        raise CFTempMailError(
            f"Cloudflare Email context missing: {target}. Make sure this address was created by the current process from the cloudflare source."
        )

    wait_seconds = int(max_wait if max_wait is not None else _email_cfg.OTP_MAX_WAIT)
    interval = max(1, int(poll_interval if poll_interval is not None else _email_cfg.OTP_POLL_INTERVAL))
    settle = max(0, int(settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS))
    after = float(after_ts if after_ts is not None else time.time()) - 30
    deadline = time.monotonic() + max(0, wait_seconds)

    best_otp: str | None = None
    best_timestamp = float("-inf")
    best_message_key = ""
    settle_until: float | None = None
    last_error = "Inbox is empty or no new OpenAI verification code has appeared yet"
    target_lower = target.lower()

    logger.info("[Cloudflare] Start polling email %s, for at most %ss", target, wait_seconds)

    while time.monotonic() < deadline:
        try:
            messages = list_messages(account.jwt)
        except CFTempMailError as exc:
            last_error = str(exc)
            logger.warning("[Cloudflare] Failed to fetch emails: %s", exc)
            time.sleep(interval)
            continue

        if messages:
            logger.debug("[Cloudflare] Received %s emails this round", len(messages))

        for item in messages:
            addresses = _message_addresses(item)
            if addresses and not any(target_lower == a or target_lower in a for a in addresses):
                continue

            detail = item
            msg_id = _message_id(item)
            otp_probe = _otp_item(detail)
            # Try details when list fields are insufficient
            if (not otp_probe.get("text") and not otp_probe.get("html")) or not looks_like_openai_email(otp_probe):
                if msg_id:
                    fetched = get_message_detail(account.jwt, msg_id)
                    if fetched:
                        merged = dict(item)
                        merged.update(fetched)
                        detail = merged
                        otp_probe = _otp_item(detail)

            otp_item = otp_probe
            if not looks_like_openai_email(otp_item):
                logger.debug(
                    "[Cloudflare] Skip non-OpenAI email id=%s from=%s subject=%s",
                    msg_id,
                    str(otp_item.get("from") or "")[:80],
                    str(otp_item.get("subject") or "")[:80],
                )
                continue

            ts = _message_timestamp(detail)
            if ts is not None and ts < after:
                logger.info(
                    "[Cloudflare] Skip stale email id=%s ts=%s after=%s subject=%s",
                    msg_id,
                    int(ts),
                    int(after),
                    str(otp_item.get("subject") or "")[:60],
                )
                continue

            otp = extract_otp(otp_item)
            if not otp:
                logger.info(
                    "[Cloudflare] OpenAI email: failed to extract a 6-digit code id=%s subject=%s",
                    msg_id,
                    str(otp_item.get("subject") or "")[:80],
                )
                continue

            message_key = msg_id or f"{otp_item.get('subject')}|{otp}|{ts}"
            effective_ts = ts if ts is not None else time.time()
            if effective_ts > best_timestamp or (
                effective_ts == best_timestamp and message_key != best_message_key and best_otp != otp
            ):
                if best_otp and best_otp != otp:
                    logger.info("[Cloudflare] Found a later OTP=%s, replacing %s", otp, best_otp)
                elif not best_otp:
                    logger.info("[Cloudflare] Locked OTP candidate %s, waiting settle=%ss", otp, settle)
                best_otp = otp
                best_timestamp = effective_ts
                best_message_key = message_key
                settle_until = time.monotonic() + settle
            elif message_key == best_message_key and best_otp == otp:
                # Same email does not reset settle
                pass

        now = time.monotonic()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info("[Cloudflare] settle completed, returning OTP=%s", best_otp)
            return best_otp

        remaining = max(0, int(deadline - now))
        if best_otp and settle_until is not None:
            logger.info(
                "[Cloudflare] Candidate OTP=%s exists, settle remaining ~%ss, total remaining %ss",
                best_otp,
                max(0, int(settle_until - now)),
                remaining,
            )
        else:
            logger.info(
                "[Cloudflare] No usable OTP matched yet, retrying in %ss (remaining %ss; emails this round=%s)",
                interval,
                remaining,
                len(messages),
            )
        if remaining <= 0:
            break
        time.sleep(min(interval, max(1, remaining)))

    if best_otp:
        logger.warning("[Cloudflare] Overall timeout but a candidate exists, returning OTP=%s", best_otp)
        return best_otp

    raise CFTempMailError(f"Timed out waiting for Cloudflare verification code: {target}; {last_error}")
