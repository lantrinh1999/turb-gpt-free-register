# -*- coding: utf-8 -*-
"""Domain email MailCode: idempotent purchase, channel initialization, and code retrieval by email cursor."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import requests

from config import email as _cfg

logger = logging.getLogger(__name__)
_PREFIX = "/api/open/v1"
_CONTEXT_CACHE: dict[str, "MailCodeAccount"] = {}
_LOCK = threading.RLock()
_PURCHASE_LOCK = threading.Lock()
_STATE_DIR = Path(__file__).resolve().parents[1] / "cache" / "mailcode"


class MailCodeError(RuntimeError):
    def __init__(self, message, *, status=0, code="", retry_after=0):
        super().__init__(message)
        self.status, self.code, self.retry_after = status, code, retry_after


def _base():
    # Fixed official service; does not accept old .env or runtime config redirecting the API Key.
    return "https://mailcode.bzb.qzz.io"


def _key():
    key = str(getattr(_cfg, "MAILCODE_API_KEY", "") or "").strip()
    if not key:
        raise MailCodeError("MailCode API Key not configured (Settings, Email / OTP, Domain Email MailCode)")
    return key


def _request(method, path, *, params=None, body=None, idempotency_key=None):
    headers = {"Authorization": "Bearer " + _key(), "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    try:
        response = requests.request(method, _base() + _PREFIX + path, params=params, json=body,
                                    headers=headers, timeout=max(1, int(_cfg.MAILCODE_REQUEST_TIMEOUT)),
                                    allow_redirects=False)
    except requests.RequestException as exc:
        # Do not output the full URL/request headers, to avoid leaking credentials.
        raise MailCodeError(f"MailCode network request failed:{type(exc).__name__}") from exc
    try:
        delay = max(0, float(response.headers.get("Retry-After", 0)))
    except (TypeError, ValueError):
        delay = 0
    try:
        payload = response.json()
    except ValueError as exc:
        raise MailCodeError(f"MailCode response is not JSON,HTTP {response.status_code}",
                            status=response.status_code, retry_after=delay) from exc
    if not isinstance(payload, dict):
        raise MailCodeError("MailCode invalid response structure", status=response.status_code)
    error = payload.get("error") or {}
    if not 200 <= response.status_code < 300 or error:
        code = str(error.get("code", "")) if isinstance(error, dict) else ""
        message = str(error.get("message", "")) if isinstance(error, dict) else ""
        raise MailCodeError(f"MailCode HTTP {response.status_code} {code}: {message}; request_id={payload.get('request_id', '-')}",
                            status=response.status_code, code=code, retry_after=delay)
    if "data" not in payload:
        raise MailCodeError("MailCode response is missing data", status=response.status_code)
    return payload["data"]


def _pages(path):
    offset = 0
    while True:
        rows = _request("GET", path, params={"offset": offset, "limit": 100})
        if not isinstance(rows, list):
            raise MailCodeError("MailCode paged response data is not an array")
        yield from rows
        if len(rows) < 100:
            break
        offset += 100


def list_products():
    return list(_pages("/products"))


def get_wallet():
    return _request("GET", "/wallet")


def list_orders():
    return list(_pages("/orders"))


def get_order(order_id):
    return _request("GET", "/orders/" + quote(str(order_id), safe=""))


def list_mailboxes():
    return list(_pages("/mailboxes"))


def _mailbox_path(mailbox_id, suffix):
    return "/mailboxes/" + quote(str(mailbox_id), safe="") + suffix


def get_code_channel(mailbox_id):
    return _request("GET", _mailbox_path(mailbox_id, "/code-channel"))


def get_codes(mailbox_id, after_sequence=None):
    params = {"limit": 100}
    if after_sequence is not None:
        params["after_sequence"] = str(after_sequence)
    data = _request("GET", _mailbox_path(mailbox_id, "/codes"), params=params)
    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
        raise MailCodeError("MailCode code retrieval response is missing the records array")
    return data


def export_code_links(ids):
    return _request("POST", "/mailboxes/code-links/export", body={"ids": ids})


def revoke_code_links(ids):
    return _request("POST", "/mailboxes/code-links/revoke", body={"ids": ids})


@dataclass
class MailCodeAccount:
    email: str
    mailbox_id: str
    order_id: str = ""
    next_sequence: str = "0"
    lock: object = field(default_factory=threading.RLock, repr=False)


def get_account_context(email):
    with _LOCK:
        return _CONTEXT_CACHE.get(str(email or "").strip().lower())


def _remember(account):
    with _LOCK:
        _CONTEXT_CACHE[account.email.lower()] = account
    return account


def _context_path(email):
    identity = hashlib.sha256((_base() + "\0" + _key() + "\0" + email.lower()).encode()).hexdigest()
    return _STATE_DIR / "contexts" / (identity + ".json")


def _save_context(account):
    _save_pending(_context_path(account.email), {
        "email": account.email, "mailbox_id": account.mailbox_id,
        "order_id": account.order_id, "next_sequence": account.next_sequence,
    })


def _cursor(data, current):
    value = str(data.get("next_sequence", current))
    if not re.fullmatch(r"[0-9]+", value) or int(value) > 9000000000000000000:
        raise MailCodeError("MailCode returned an invalid next_sequence")
    return value  # Use the server cursor as is: do not add 1, and do not deduplicate by verification code digits.


def _prepare(account):
    """Initialize IMAP on demand at the first code retrieval; the address is handed to the registration flow only after READY."""
    deadline = time.monotonic() + max(1, int(_cfg.MAILCODE_CHANNEL_WAIT_SECONDS))
    while True:
        try:
            data = get_codes(account.mailbox_id)  # Get the latest watermark without passing a cursor; do not read the entire history.
        except MailCodeError as exc:
            if exc.status not in {0, 429, 500, 502, 503, 504}:
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(max(5, exc.retry_after), remaining))
            continue
        account.next_sequence = _cursor(data, account.next_sequence)
        if data.get("channel_status") == "READY":
            _save_context(account)
            return
        if data.get("channel_status") in {"PAUSED", "CLOSED"}:
            raise MailCodeError(f"MailCode channel unavailable:{data.get('channel_status')}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise MailCodeError("MailCode Code retrieval channel initialization timed out; the purchased email is kept, initialization continues on the next claim, and it is not purchased again")
        time.sleep(min(5, remaining))


def _pending_path(product):
    # The API Key is not saved; the pending purchase is persisted, so the original idempotency key keeps being used even after network loss or restart.
    identity = hashlib.sha256((_base() + "\0" + _key() + "\0" + product).encode()).hexdigest()
    return _STATE_DIR / "purchases" / (identity + ".json")


def _save_pending(path, pending):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(pending), encoding="utf-8")
    temp.replace(path)


def pick_account():
    product = str(getattr(_cfg, "MAILCODE_PRODUCT_ID", "product_a3783a0ead074b4091631b9ad04153f9") or "").strip()
    if not product:
        raise MailCodeError("MailCode Product ID is not configured, fill in MAILCODE_PRODUCT_ID")
    with _PURCHASE_LOCK:
        path = _pending_path(product)
        pending = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"key": "turb-mailcode-" + uuid.uuid4().hex}
        _save_pending(path, pending)  # Must be saved before the charge is initiated.
        if "item" not in pending:
            for attempt in range(3):
                try:
                    data = _request("POST", "/orders", body={"product_id": product, "count": 1}, idempotency_key=pending["key"])
                    if not isinstance(data, dict) or data.get("status") != "COMPLETED" or len(data.get("items") or []) != 1:
                        raise MailCodeError("MailCode Invalid purchase response structure; keep the original idempotency key and do not place a new order")
                    item = data["items"][0]
                    if not item.get("mailbox_id") or "@" not in str(item.get("email", "")) or item.get("status") != "ACTIVE":
                        raise MailCodeError("MailCode Purchase response is missing a valid email; keep the original idempotency key")
                    pending.update(item=item, order_id=data.get("order_id", ""))
                    _save_pending(path, pending)
                    break
                except MailCodeError as exc:
                    retryable = exc.status == 0 or exc.status == 429 or exc.status >= 500
                    if not retryable:
                        if exc.status in {400, 401, 403, 404, 409, 413} and exc.code != "IDEMPOTENCY_CONFLICT":
                            path.unlink(missing_ok=True)
                        raise
                    if attempt == 2:
                        raise MailCodeError(f"{exc}; purchase result not confirmed, idempotency key saved, the original request will continue next time") from exc
                    time.sleep(max(1, exc.retry_after))
        item = pending["item"]
        account = _remember(MailCodeAccount(item["email"], item["mailbox_id"], pending.get("order_id", "")))
        _prepare(account)
        path.unlink(missing_ok=True)
    logger.info("[MailCode] Email channel READY:%s", account.email)
    return account


def get_email():
    return pick_account().email


def release_account(email, status="available", note=None):
    # The platform has no user refund API; releasing the local context cannot refund/revoke the purchased email.
    with _LOCK:
        _CONTEXT_CACHE.pop(str(email or "").strip().lower(), None)


def _restore(email):
    path = _context_path(email)
    if path.exists():
        saved = json.loads(path.read_text(encoding="utf-8"))
        return _remember(MailCodeAccount(**saved))
    for row in _pages("/mailboxes"):
        if str(row.get("email", "")).lower() == email.lower() and row.get("id"):
            # On recovery, start from historical cursor 0 and filter by after_ts/validity period, without purchasing again.
            return _remember(MailCodeAccount(row["email"], row["id"]))
    raise MailCodeError(f"MailCode Purchased email does not exist or its usage right has expired:{email}")


def fetch_latest_otp(email, after_ts=None, max_wait=None, poll_interval=None, settle_seconds=None):
    account = get_account_context(email) or _restore(str(email).strip())
    deadline = time.monotonic() + max(0, int(_cfg.OTP_MAX_WAIT if max_wait is None else max_wait))
    interval = max(5, int(_cfg.OTP_POLL_INTERVAL if poll_interval is None else poll_interval))
    settle = max(0, int(_cfg.OTP_SETTLE_SECONDS if settle_seconds is None else settle_seconds))
    best, best_order, settle_until = None, (-1, -1), None
    last_error = "No new verification code yet"
    with account.lock:
        while True:
            delay = interval
            try:
                data = get_codes(account.mailbox_id, account.next_sequence)
                for record in data["records"]:
                    code = record.get("code")
                    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
                        continue
                    received = float(record.get("received_at") or 0) / 1000
                    expires = float(record.get("expires_at") or 0) / 1000
                    if (after_ts is not None and received < after_ts) or (expires and expires <= time.time()):
                        continue
                    order = (received, int(record.get("sequence") or 0))
                    if order > best_order:
                        best, best_order, settle_until = code, order, time.monotonic() + settle
                previous = account.next_sequence
                account.next_sequence = _cursor(data, previous)
                _save_context(account)
                if data.get("has_more"):
                    if account.next_sequence == previous:
                        raise MailCodeError("MailCode pagination cursor did not advance")
                    if time.monotonic() < deadline:
                        continue
                if best and time.monotonic() >= settle_until:
                    return best
                if data.get("channel_status") in {"CLOSED", "PAUSED"}:
                    raise MailCodeError("MailCode code retrieval channel closed/paused", status=404)
            except MailCodeError as exc:
                if exc.status in {400, 401, 403, 404}:
                    raise
                last_error = str(exc)
                delay = max(interval, exc.retry_after)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(delay, remaining))
    if best:
        return best
    raise MailCodeError(f"Timed out waiting for MailCode verification code: {email};{last_error}")
