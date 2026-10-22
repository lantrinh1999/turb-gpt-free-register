# -*- coding: utf-8 -*-
"""CloudMail/Cloud Mail API email client."""
from __future__ import annotations

import logging
import random
import re
import secrets
import string
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp, looks_like_openai_email

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 20


class CloudMailError(RuntimeError):
    """CloudMail/Cloud Mail service request or email code retrieval failed."""


@dataclass
class CloudMailAccount:
    email: str
    domain: str


_CONTEXT_CACHE: dict[str, CloudMailAccount] = {}
_DOMAIN_CACHE: tuple[float, list[str]] | None = None
DOMAIN_CACHE_TTL = 300


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _base_url(value: str | None = None) -> str:
    base = str(value if value is not None else getattr(_email_cfg, "CLOUDMAIL_API_BASE", "") or "").strip().rstrip("/")
    if not base:
        raise CloudMailError("CloudMail API address is not configured, fill in CLOUDMAIL_API_BASE (for example https://your-worker-custom-domain).")
    if not re.match(r"^https?://", base, re.I):
        base = "https://" + base
    return base


def _token() -> str:
    token = str(getattr(_email_cfg, "CLOUDMAIL_AUTH_TOKEN", "") or "").strip()
    if not token:
        raise CloudMailError("CloudMail Authorization Token is not configured, fill in CLOUDMAIL_AUTH_TOKEN.")
    return token


def _token_path_candidates(path: str | None = None) -> list[str]:
    first = str(path or getattr(_email_cfg, "CLOUDMAIL_TOKEN_PATH", "") or "/api/public/genToken").strip()
    out = []
    for item in (first, "/api/public/genToken"):
        if not item:
            continue
        if not item.startswith("/"):
            item = "/" + item
        if item not in out:
            out.append(item)
    return out


def _extract_token(payload: dict) -> str:
    data = payload.get("data") if isinstance(payload, dict) else None
    candidates = []
    if isinstance(payload, dict):
        candidates.extend([payload.get("token"), payload.get("accessToken"), payload.get("access_token")])
    if isinstance(data, dict):
        candidates.extend([data.get("token"), data.get("accessToken"), data.get("access_token"), data.get("authorization")])
    if isinstance(data, str):
        candidates.append(data)
    for item in candidates:
        token = str(item or "").strip()
        if token:
            return token
    raise CloudMailError(f"CloudMail Token generated successfully but not found in the response token: {str(payload)[:200]}")


def gen_token(email: str | None = None, password: str | None = None, path: str | None = None, base_url: str | None = None) -> str:
    """Generate an Authorization Token with the CloudMail admin email/password."""
    email = str(email if email is not None else getattr(_email_cfg, "CLOUDMAIL_ADMIN_EMAIL", "") or "").strip()
    password = str(password if password is not None else getattr(_email_cfg, "CLOUDMAIL_PASSWORD", "") or "").strip()
    if not email or not password:
        raise CloudMailError("CloudMail admin email or password is empty")

    last_error = ""
    for token_path in _token_path_candidates(path):
        url = _base_url(base_url) + token_path
        try:
            resp = requests.post(
                url,
                json={"email": email, "password": password},
                headers={"Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
            payload = resp.json()
        except Exception as exc:
            last_error = f"{token_path}: {type(exc).__name__}: {exc}"
            continue
        code = payload.get("code") if isinstance(payload, dict) else None
        if resp.status_code < 400 and code in (200, "200", None):
            try:
                token = _extract_token(payload)
                logger.info("[CloudMail] token generated successfully: path=%s", token_path)
                return token
            except CloudMailError as exc:
                last_error = str(exc)
                continue
        message = payload.get("message") if isinstance(payload, dict) else ""
        last_error = f"{token_path}: HTTP {resp.status_code}; code={code}; {message or str(payload)[:160]}"
    raise CloudMailError(f"CloudMail Token generation failed: {last_error}")


# Compatible with the old internal call name.
def login(username: str | None = None, password: str | None = None, path: str | None = None, base_url: str | None = None) -> str:
    return gen_token(email=username, password=password, path=path, base_url=base_url)


def _domains() -> list[str]:
    raw = getattr(_email_cfg, "CLOUDMAIL_DOMAINS", []) or []
    out = _normalize_domains(raw)
    if not out:
        out = fetch_domains()
    if not out:
        raise CloudMailError("CloudMail email domain list is empty and could not be fetched automatically from the platform.")
    return out


def _request(path: str, body: dict | None = None):
    url = _base_url() + path
    try:
        resp = requests.post(
            url,
            json=body or {},
            headers={"Authorization": _token(), "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise CloudMailError(f"CloudMail Request failed ({path}): {type(exc).__name__}: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError as exc:
        raise CloudMailError(f"CloudMail response is not JSON ({path}): HTTP {resp.status_code}") from exc

    code = payload.get("code") if isinstance(payload, dict) else None
    if resp.status_code >= 400 or code not in (200, "200"):
        message = payload.get("message") if isinstance(payload, dict) else ""
        raise CloudMailError(f"CloudMail Request failed ({path}): HTTP {resp.status_code}; code={code}; {message or str(payload)[:200]}")
    return payload.get("data")


def _request_raw(method: str, path: str, *, body: dict | None = None, token: str | None = None):
    url = _base_url() + path
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = token
    try:
        if method.upper() == "GET":
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        else:
            resp = requests.post(url, json=body or {}, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise CloudMailError(f"CloudMail Request failed ({path}): {type(exc).__name__}: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError as exc:
        raise CloudMailError(f"CloudMail response is not JSON ({path}): HTTP {resp.status_code}") from exc

    code = payload.get("code") if isinstance(payload, dict) else None
    if resp.status_code >= 400 or code not in (200, "200", None):
        message = payload.get("message") if isinstance(payload, dict) else ""
        raise CloudMailError(f"CloudMail Request failed ({path}): HTTP {resp.status_code}; code={code}; {message or str(payload)[:200]}")
    return payload


def _normalize_domains(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = raw.replace(";", "\n").replace(",", "\n").splitlines()
    elif isinstance(raw, dict):
        parts = []
        for key in ("domain", "name", "value", "emailDomain"):
            if raw.get(key):
                parts.append(raw.get(key))
    else:
        try:
            parts = list(raw)
        except TypeError:
            parts = [raw]
    out = []
    for item in parts:
        if isinstance(item, dict):
            candidates = [item.get(k) for k in ("domain", "name", "value", "emailDomain")]
        else:
            candidates = [item]
        for candidate in candidates:
            domain = str(candidate or "").strip().lower().lstrip("@")
            if domain and "." in domain and " " not in domain and domain not in out:
                out.append(domain)
    return out


def _extract_domains(payload) -> list[str]:
    if not isinstance(payload, dict):
        return _normalize_domains(payload)
    data = payload.get("data") if "data" in payload else payload
    candidates = []
    if isinstance(data, dict):
        for key in ("domainList", "domains", "domain", "emailDomains", "mailDomains", "availDomains"):
            candidates.append(data.get(key))
    candidates.append(data)
    for item in candidates:
        domains = _normalize_domains(item)
        if domains:
            return domains
    return []


def _login_token() -> str:
    email = str(getattr(_email_cfg, "CLOUDMAIL_ADMIN_EMAIL", "") or "").strip()
    password = str(getattr(_email_cfg, "CLOUDMAIL_PASSWORD", "") or "").strip()
    if not email or not password:
        raise CloudMailError("CloudMail admin email or password is empty, cannot log in to fetch the domain list")
    payload = _request_raw("POST", "/api/login", body={"email": email, "password": password})
    token = _extract_token(payload)
    logger.info("[CloudMail] admin login succeeded, can be used to fetch the hidden domain list")
    return token


def fetch_domains(force: bool = False) -> list[str]:
    """Fetch the available email domain list from the CloudMail platform.

    Prefer reading the public website config `/api/setting/websiteConfig`; if the site hides domains on the login page,
    then log in with the admin account and read `/api/setting/query`.
    """
    global _DOMAIN_CACHE
    now = time.monotonic()
    if not force and _DOMAIN_CACHE and now - _DOMAIN_CACHE[0] < DOMAIN_CACHE_TTL:
        return list(_DOMAIN_CACHE[1])

    errors: list[str] = []
    for method, path, token in (
        ("GET", "/api/setting/websiteConfig", None),
        ("GET", "/api/setting/query", "__login__"),
    ):
        try:
            auth = _login_token() if token == "__login__" else token
            payload = _request_raw(method, path, token=auth)
            domains = _extract_domains(payload)
            if domains:
                _DOMAIN_CACHE = (now, domains)
                logger.info("[CloudMail] Fetched available domains from the platform:%s", ",".join(domains))
                return list(domains)
            errors.append(f"{path}: response has no domainList")
        except Exception as exc:
            errors.append(f"{path}: {type(exc).__name__}: {exc}")

    raise CloudMailError("CloudMail failed to fetch domains automatically:" + ";".join(errors))


def _random_local_part(length: int | None = None) -> str:
    length = int(length or getattr(_email_cfg, "CLOUDMAIL_RANDOM_LOCAL_LENGTH", 12) or 12)
    length = max(6, min(32, length))
    alphabet = string.ascii_lowercase + string.digits
    # Start with a letter to reduce compatibility issues with email providers for purely numeric/special prefixes.
    return random.choice(string.ascii_lowercase) + "".join(secrets.choice(alphabet) for _ in range(length - 1))


def generate_email() -> str:
    domain = random.choice(_domains())
    return f"{_random_local_part()}@{domain}"


def _add_user(email: str) -> None:
    password = secrets.token_urlsafe(12)
    _request("/api/public/addUser", {"list": [{"email": email, "password": password}]})


def pick_account() -> CloudMailAccount:
    email = generate_email()
    domain = email.rsplit("@", 1)[1]
    if bool(getattr(_email_cfg, "CLOUDMAIL_AUTO_ADD_USER", True)):
        _add_user(email)
        logger.info("[CloudMail] Added random email user: %s", email)
    else:
        logger.info("[CloudMail] Generated random email: %s (addUser not called)", email)
    account = CloudMailAccount(email=email, domain=domain)
    _CONTEXT_CACHE[_cache_key(email)] = account
    return account


def get_email() -> str:
    return pick_account().email


def get_account_context(email: str) -> CloudMailAccount | None:
    return _CONTEXT_CACHE.get(_cache_key(email))


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    _CONTEXT_CACHE.pop(_cache_key(email), None)
    logger.info("[CloudMail] Released email context: %s (status=%s, note=%s)", email, status, note or "")


def _parse_time(raw) -> float | None:
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        pass
    text = str(raw).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            # The docs state createTime is UTC.
            return datetime.strptime(text.replace("Z", ""), fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _otp_item(mail: dict) -> dict:
    return {
        "id": mail.get("emailId") or mail.get("id"),
        "from": mail.get("sendEmail") or mail.get("from") or "",
        "subject": mail.get("subject") or "",
        "text": mail.get("text") or "",
        "html": mail.get("content") or mail.get("html") or "",
    }


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    target = str(email or "").strip()
    if not target:
        raise CloudMailError("CloudMail code retrieval is missing the email address")

    wait_seconds = int(max_wait if max_wait is not None else _email_cfg.OTP_MAX_WAIT)
    interval = max(1, int(poll_interval if poll_interval is not None else _email_cfg.OTP_POLL_INTERVAL))
    settle = max(0, int(settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS))
    deadline = time.monotonic() + max(0, wait_seconds)
    best_otp: str | None = None
    best_timestamp = float("-inf")
    settle_until: float | None = None
    last_error = "Inbox is empty or no new OpenAI verification code has appeared yet"

    logger.info("[CloudMail] Start polling email %s, for at most %ss", target, wait_seconds)
    while time.monotonic() <= deadline:
        try:
            mails = _request(
                "/api/public/emailList",
                {
                    "toEmail": target,
                    "timeSort": "desc",
                    "type": 0,
                    "isDel": 0,
                    "num": 1,
                    "size": 20,
                },
            )
            if not isinstance(mails, list):
                raise CloudMailError("CloudMail email query response data is not an array")
            for mail in sorted(mails, key=lambda item: _parse_time((item or {}).get("createTime")) or float("-inf"), reverse=True):
                if not isinstance(mail, dict):
                    continue
                ts = _parse_time(mail.get("createTime"))
                if after_ts is not None and ts is not None and ts < after_ts - 30:
                    continue
                item = _otp_item(mail)
                if not looks_like_openai_email(item):
                    continue
                otp = extract_otp(item)
                if not otp:
                    continue
                candidate_time = float("-inf") if ts is None else ts
                if best_otp is None or candidate_time > best_timestamp or (candidate_time == best_timestamp and otp != best_otp):
                    best_otp = otp
                    best_timestamp = candidate_time
                    settle_until = time.monotonic() + settle
                    logger.info("[CloudMail] Locked OTP candidate, waiting %ss for confirmation", settle)

            now = time.monotonic()
            if best_otp and settle_until is not None and now >= settle_until:
                return best_otp
        except CloudMailError as exc:
            last_error = str(exc)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    if best_otp:
        return best_otp
    raise CloudMailError(f"Timed out waiting for CloudMail verification code: {target}; {last_error}")
