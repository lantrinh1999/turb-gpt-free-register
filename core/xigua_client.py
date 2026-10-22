# -*- coding: utf-8 -*-
"""Xigua (xigua.dasiqo.com) email code-receiving API client."""
from __future__ import annotations
import logging, re, threading, time, uuid
from dataclasses import dataclass
import requests
from config import email as _cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)
_CODE_RE = re.compile(r"\b(\d{6})\b")
_CACHE: dict[str, "XiguaAccount"] = {}
_LAST_CODES: dict[str, str] = {}
_LOCK = threading.RLock()

class XiguaError(RuntimeError): pass

@dataclass
class XiguaAccount:
    email: str
    order_id: str

def _base():
    return str(getattr(_cfg, "XIGUA_API_BASE", "https://xigua.dasiqo.com") or "https://xigua.dasiqo.com").rstrip("/")

def _key():
    key = str(getattr(_cfg, "XIGUA_API_KEY", "") or "").strip()
    if not key: raise XiguaError("Xigua API Key is not configured, fill it in under Settings → Email / OTP XIGUA_API_KEY")
    return key

def _request(method, path, *, body=None, auth=True, params=None, extra_headers=None):
    headers = {"Accept": "application/json"}
    if auth: headers["Authorization"] = "Bearer " + _key()
    if body is not None: headers["Content-Type"] = "application/json"
    if extra_headers: headers.update(extra_headers)
    try:
        r = requests.request(method, _base() + path, json=body, params=params, headers=headers,
                             timeout=max(1, min(120, int(getattr(_cfg, "XIGUA_REQUEST_TIMEOUT", 20) or 20))))
    except requests.RequestException as exc:
        raise XiguaError(f"Xigua request failed ({method} {path}): {exc}") from exc
    try: payload = r.json()
    except ValueError as exc: raise XiguaError(f"Xigua response is not JSON ({path})") from exc
    if r.status_code >= 400:
        err = payload.get("error") if isinstance(payload, dict) else None
        msg = err.get("message") if isinstance(err, dict) else payload.get("message") if isinstance(payload, dict) else ""
        raise XiguaError(f"Xigua request failed ({path}): HTTP {r.status_code}; {msg or payload}")
    return payload

def _unwrap(payload):
    if isinstance(payload, dict):
        return payload.get("data") if isinstance(payload.get("data"), dict) else payload
    return payload

def pick_account() -> XiguaAccount:
    wanted = str(getattr(_cfg, "XIGUA_OFFER_ID", "") or "").strip()
    if not wanted:
        raise XiguaError("Xigua Offer ID is not configured, fill it in under Settings → Email / OTP → Xigua XIGUA_OFFER_ID")
    # Always use the offer_id from the config; do not automatically query or switch to other plans.
    offer = {"id": wanted}
    payload = _request("POST", "/api/v1/orders", body={"offer_id": offer["id"]},
                       params=None, auth=True, extra_headers={"Idempotency-Key": "turb-xigua-" + str(uuid.uuid4())})
    data = _unwrap(payload)
    email, order_id = str(data.get("email") or "").strip(), str(data.get("id") or "").strip()
    if not email or not order_id: raise XiguaError(f"Xigua order response is missing email/id: {data}")
    account = XiguaAccount(email, order_id)
    with _LOCK: _CACHE[email.lower()] = account
    logger.info("[Xigua] Claimed email: %s order=%s", email, order_id)
    return account

def get_email(): return pick_account().email
def get_account_context(email):
    with _LOCK: return _CACHE.get(str(email or "").strip().lower())
def release_account(email, status="available", note=None):
    key = str(email or "").strip().lower()
    with _LOCK: account = _CACHE.pop(key, None)
    # If the registration flow fails before the email is consumed, actively cancel the Xigua order and release the platform stock/frozen resources.
    if account and str(status or "").lower() in {"available", "failed", "cancelled", "error"}:
        try:
            _request("POST", "/api/v1/orders/" + account.order_id + "/cancel", body={})
            logger.info("[Xigua] Canceled unused order: %s order=%s", account.email, account.order_id)
        except Exception as exc:
            logger.warning("[Xigua] Failed to cancel order: order=%s error=%s", account.order_id, exc)
    _LAST_CODES.pop(key, None)

def fetch_latest_otp(email, after_ts=0, max_wait=None, poll_interval=None, settle_seconds=None):
    account = get_account_context(email)
    if account is None:
        # After a process restart, restore the most recent order by account email, so registered accounts do not lose their pickup context.
        try:
            payload = _request("GET", "/api/v1/orders")
            items = payload if isinstance(payload, list) else (payload.get("items", []) if isinstance(payload, dict) else [])
            target = str(email or "").casefold()
            for item in items:
                if str(item.get("email") or "").casefold() == target and item.get("id"):
                    account = XiguaAccount(str(item["email"]), str(item["id"]))
                    with _LOCK: _CACHE[target] = account
                    break
        except Exception:
            account = None
    if account is None: raise XiguaError(f"Xigua email context does not exist: {email}")
    deadline = time.monotonic() + int(max_wait if max_wait is not None else getattr(_cfg, "OTP_MAX_WAIT", 90) or 90)
    interval = max(1, int(poll_interval if poll_interval is not None else getattr(_cfg, "XIGUA_POLL_INTERVAL", 5) or 5))
    attempts = max(1, int(getattr(_cfg, "XIGUA_POLL_ATTEMPTS", 10) or 10))
    candidate = None
    confirmations = 0
    for _attempt in range(attempts):
        if time.monotonic() > deadline:
            break
        data = _unwrap(_request("GET", "/api/v1/orders/" + account.order_id))
        code = (data.get("code") or data.get("verification_code") or data.get("verificationCode")) if isinstance(data, dict) else None
        direct_code = False
        if code:
            m = _CODE_RE.search(str(code))
            if m:
                direct_code = True
                found = m.group(1)
                if found == candidate:
                    confirmations += 1
                else:
                    candidate, confirmations = found, 1
                if confirmations >= 2 and found != _LAST_CODES.get(account.email.lower()):
                    logger.info("[Xigua] Verification code confirmed 2 times in a row: %s", found)
                    _LAST_CODES[account.email.lower()] = found
                    return found
        text = " ".join(str(data.get(k, "")) for k in ("subject", "body", "body_preview", "message")) if isinstance(data, dict) else ""
        code = extract_otp({"subject": text, "body": text, "text": text})
        if code and not direct_code:
            if code == candidate:
                confirmations += 1
            else:
                candidate, confirmations = code, 1
            if confirmations >= 2 and code != _LAST_CODES.get(account.email.lower()):
                logger.info("[Xigua] Verification code confirmed 2 times in a row: %s", code)
                _LAST_CODES[account.email.lower()] = code
                return code
        time.sleep(min(interval, max(0, deadline - time.monotonic())))
    raise XiguaError(f"Timed out waiting for Xigua verification code: {email}")
