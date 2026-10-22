# -*- coding: utf-8 -*-
"""Remail open API email client.

Remail open API differs from the existing generate-random-email services in this project:

1. First use the API Key to place a ``code`` or ``purchase`` order under the project;
2. The order returns the delivered email and a service token that belongs only to that order;
3. Code retrieval uses ``/v1/pickup``, no longer carries the API Key, and carries only the email and service token.

Therefore the service token must be saved in the current process context together with the email; do not rely only on the email address
to reassemble the pickup request.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://remail.aishop6.com"
REQUEST_TIMEOUT = 20
_CODE_RE = re.compile(r"\b(\d{6})\b")
_FINAL_ORDER_STATUSES = {"failed", "refunded", "closed"}


class RemailError(RuntimeError):
    """Remail API request, order placement, or code retrieval failed."""


# Compatible with names callers may use.
RemailClientError = RemailError


@dataclass
class RemailAccount:
    """Pickup context of one Remail order."""

    email: str
    service_token: str
    order_no: str
    project_id: int
    email_suffix: str


_CONTEXT_CACHE: dict[str, RemailAccount] = {}
_CONTEXT_LOCK = threading.RLock()


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _base_url(value: str | None = None) -> str:
    """Return the API root URL; also tolerates users mistakenly entering the docs URL ``.../docs``."""
    raw = str(
        value if value is not None else getattr(_email_cfg, "REMAIL_API_BASE", DEFAULT_API_BASE) or DEFAULT_API_BASE
    ).strip()
    if not raw:
        raw = DEFAULT_API_BASE
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw

    parsed = urlsplit(raw.rstrip("/"))
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise RemailError("Remail API URL is invalid, enter https://remail.aishop6.com (do not enter an API path)")

    path = parsed.path.rstrip("/")
    # The docs link can be pasted directly into the settings page; the API actually lives at the root path of the same domain.
    if path.lower() == "/docs":
        path = ""
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", "")).rstrip("/")


def _request_timeout() -> int:
    try:
        value = int(getattr(_email_cfg, "REMAIL_REQUEST_TIMEOUT", REQUEST_TIMEOUT) or REQUEST_TIMEOUT)
    except (TypeError, ValueError):
        value = REQUEST_TIMEOUT
    return max(1, min(120, value))


def _api_key() -> str:
    value = str(getattr(_email_cfg, "REMAIL_API_KEY", "") or "").strip()
    if not value:
        raise RemailError("Remail API Key is not configured, fill in under Settings → Email / OTP: REMAIL_API_KEY")
    return value


def _auth_headers() -> dict[str, str]:
    return {"Accept": "application/json", "Authorization": f"Bearer {_api_key()}"}


def _error_message(payload, response) -> str:
    if isinstance(payload, dict):
        message = payload.get("message") or payload.get("error") or payload.get("detail")
        request_id = payload.get("requestId") or payload.get("request_id")
        if message:
            return f"{message} (requestId={request_id})" if request_id else str(message)
    text = str(getattr(response, "text", "") or "").strip()
    return text[:240] if text else "The server returned no error message"


def _request(
    method: str,
    path: str,
    *,
    params: dict | None = None,
    json_body: dict | None = None,
    headers: dict[str, str] | None = None,
    authenticated: bool = True,
):
    """Call the Remail API and return the JSON payload.

    ``authenticated=False`` Only for the pickup endpoint. The service token is not written to logs or exception text.
    """
    request_headers = {"Accept": "application/json"}
    if authenticated:
        request_headers.update(_auth_headers())
    if headers:
        request_headers.update(headers)

    url = _base_url() + (path if str(path).startswith("/") else f"/{path}")
    try:
        response = requests.request(
            method.upper(),
            url,
            params=params,
            json=json_body,
            headers=request_headers,
            timeout=_request_timeout(),
        )
    except requests.RequestException as exc:
        raise RemailError(f"Remail Request failed ({method.upper()} {path}): {type(exc).__name__}: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        if response.status_code >= 400:
            raise RemailError(
                f"Remail Request failed ({method.upper()} {path}): HTTP {response.status_code}; "
                f"{_error_message(None, response)}"
            ) from exc
        raise RemailError(f"Remail response is not JSON ({method.upper()} {path})") from exc

    if response.status_code >= 400:
        if response.status_code == 401 and authenticated:
            raise RemailError(f"Remail API Key is invalid or expired ({path})")
        raise RemailError(
            f"Remail Request failed ({method.upper()} {path}): HTTP {response.status_code}; "
            f"{_error_message(payload, response)}"
        )
    return payload


def _first_value(data: dict, *keys: str):
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return None


def _unwrap_order(payload) -> dict:
    """Read the Order defined by OpenAPI, and tolerate the few gateways that wrap the response in data/order."""
    if not isinstance(payload, dict):
        raise RemailError("Remail order response is not an object")
    if any(
        k in payload
        for k in ("orderNo", "order_no", "deliveryEmail", "delivery_email", "serviceToken", "service_token")
    ):
        return payload
    for key in ("data", "order"):
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    raise RemailError("Remail order response is missing order data")


def _project_id() -> int:
    raw = getattr(_email_cfg, "REMAIL_PROJECT_ID", 2)
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        value = 0
    if value <= 0:
        raise RemailError(
            "Remail Project ID is not configured, query the project via the Remail API first and then fill it in REMAIL_PROJECT_ID"
        )
    return value


def _email_suffix() -> str:
    suffix = str(getattr(_email_cfg, "REMAIL_EMAIL_SUFFIX", "outlook.com") or "").strip().lstrip("@")
    if not suffix or "@" in suffix or any(ch.isspace() for ch in suffix):
        raise RemailError("Remail Invalid email suffix, enter a domain such as outlook.com (do not enter a full email)")
    return suffix


def _supply_policy() -> str:
    value = str(getattr(_email_cfg, "REMAIL_SUPPLY_POLICY", "public_only") or "public_only").strip().lower()
    if value not in {"private_first", "public_only"}:
        raise RemailError("Remail invalid stock strategy, only private_first or public_only")
    return value


def _service_mode() -> str:
    value = str(getattr(_email_cfg, "REMAIL_SERVICE_MODE", "purchase") or "purchase").strip().lower()
    if value not in {"code", "purchase"}:
        raise RemailError("Remail invalid service mode, only code or purchase")
    return value


def _order_wait_seconds() -> int:
    try:
        value = int(getattr(_email_cfg, "REMAIL_ORDER_WAIT_SECONDS", 30) or 30)
    except (TypeError, ValueError):
        value = 30
    return max(0, min(180, value))


def _order_credentials(order: dict) -> tuple[str, str, str] | None:
    email = str(_first_value(order, "deliveryEmail", "delivery_email") or "").strip()
    token = str(_first_value(order, "serviceToken", "service_token") or "").strip()
    order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
    if email and "@" in email and token:
        return email, token, order_no
    return None


def _cache_context(account: RemailAccount) -> RemailAccount:
    """Cache the order pickup context and return the object."""
    with _CONTEXT_LOCK:
        _CONTEXT_CACHE[_cache_key(account.email)] = account
    return account


def _context_from_order(order: dict, target_email: str) -> RemailAccount | None:
    """Create the context from the order object, requiring the delivered email to match exactly."""
    credentials = _order_credentials(order)
    if not credentials:
        return None
    email, service_token, order_no = credentials
    if email.casefold() != str(target_email or "").strip().casefold():
        return None

    raw_project_id = _first_value(order, "projectId", "project_id")
    try:
        project_id = int(str(raw_project_id).strip()) if raw_project_id is not None else _project_id()
    except (TypeError, ValueError, RemailError):
        # Order details should always have projectId; when a historical endpoint lacks it, pickup is unaffected, keep
        # the current config value as a display/compatibility field.
        try:
            project_id = _project_id()
        except RemailError:
            project_id = 0

    suffix = str(
        _first_value(order, "emailSuffix", "email_suffix")
        or email.rsplit("@", 1)[-1]
        or getattr(_email_cfg, "REMAIL_EMAIL_SUFFIX", "outlook.com")
    ).strip().lstrip("@")
    return RemailAccount(
        email=email,
        service_token=service_token,
        order_no=order_no,
        project_id=project_id,
        email_suffix=suffix,
    )


def _order_list_items(payload) -> list[dict]:
    """Read the order list response, tolerating gateways that wrap it in data/items."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def _saved_context_metadata(email: str) -> dict:
    """Read the Remail order credentials saved on the account, without propagating parse failures into the main liveness check flow."""
    try:
        from core import db

        row = db.get_account_by_email(email)
    except Exception as exc:
        logger.debug("[Remail] Failed to read order info of the registered account: %s: %s", type(exc).__name__, exc)
        return {}
    if not row:
        return {}

    raw = row.get("extra_json")
    if isinstance(raw, str) and raw.strip():
        try:
            extra = json.loads(raw)
        except (TypeError, ValueError):
            extra = {}
    elif isinstance(raw, dict):
        extra = raw
    else:
        extra = {}
    if not isinstance(extra, dict):
        return {}

    # The new field uses email_service; also tolerates remail, which early development versions may have used.
    for key in ("email_service", "remail"):
        value = extra.get(key)
        if isinstance(value, dict):
            source = str(value.get("source") or "remail").strip().lower()
            if source == "remail":
                return dict(value)
    return {}


def get_account_context_metadata(email: str) -> dict | None:
    """Return the persistable Remail order context, used to save the registered account.

    service token is the pickup credential and is not logged; it is called here only by the account persistence layer, and normal list
    API endpoints do not return ``extra_json`` directly.
    """
    account = get_account_context(email)
    if account is None:
        return None
    return {
        "source": "remail",
        "email": account.email,
        "service_token": account.service_token,
        "order_no": account.order_no,
        "project_id": account.project_id,
        "email_suffix": account.email_suffix,
    }


def restore_account_context(email: str) -> RemailAccount | None:
    """Restore the Remail pickup context of a registered account.

    ``_CONTEXT_CACHE`` is lost after a process restart. Prefer the service token saved on the account,
    then look up details by the saved order number, and finally search orders by email with the API Key. All candidate orders
    must match the target email exactly (case-insensitive), to avoid taking verification codes of other emails.
    """
    target = str(email or "").strip()
    if not target:
        return None
    cached = get_account_context(target)
    if cached is not None:
        return cached

    metadata = _saved_context_metadata(target)
    saved_email = str(metadata.get("email") or "").strip()
    if saved_email and saved_email.casefold() != target.casefold():
        metadata = {}

    saved_token = str(metadata.get("service_token") or metadata.get("serviceToken") or "").strip()
    if saved_token:
        order = {
            "deliveryEmail": saved_email or target,
            "serviceToken": saved_token,
            "orderNo": str(metadata.get("order_no") or metadata.get("orderNo") or "").strip(),
            "projectId": metadata.get("project_id") or metadata.get("projectId"),
            "emailSuffix": metadata.get("email_suffix") or metadata.get("emailSuffix"),
        }
        account = _context_from_order(order, target)
        if account is not None:
            logger.info(
                "[Remail] Restored pickup context from the saved account info: %s order=%s",
                target,
                account.order_no or "-",
            )
            return _cache_context(account)

    saved_order_no = str(metadata.get("order_no") or metadata.get("orderNo") or "").strip()
    if saved_order_no:
        try:
            detail = _unwrap_order(
                _request("GET", f"/v1/open/orders/{quote(saved_order_no, safe='')}")
            )
        except RemailError as exc:
            logger.debug("[Remail] Failed to restore by the saved order number: order=%s error=%s", saved_order_no, exc)
        else:
            account = _context_from_order(detail, target)
            if account is not None:
                logger.info(
                    "[Remail] Restored pickup context by order number: %s order=%s",
                    target,
                    account.order_no or saved_order_no,
                )
                return _cache_context(account)

    # When no persisted credentials are available, query the orders belonging to the user via the API Key. The search of the list endpoint
    # search is filtered on the server side; a full email match must still be done on the client, and fuzzy hits must not be accepted.
    try:
        payload = _request(
            "GET",
            "/v1/open/orders",
            params={"search": target},
        )
    except RemailError as exc:
        logger.debug("[Remail] Failed to search orders by email: email=%s error=%s", target, exc)
        return None

    candidates = [
        item
        for item in _order_list_items(payload)
        if str(_first_value(item, "deliveryEmail", "delivery_email") or "").strip().casefold()
        == target.casefold()
    ]
    candidates.sort(
        key=lambda item: _parse_timestamp(
            _first_value(item, "updatedAt", "updated_at", "createdAt", "created_at")
        )
        or float("-inf"),
        reverse=True,
    )

    # List responses usually carry serviceToken directly; if the gateway hides the token for security policy reasons,
    # then request order details one by one (newest orders first).
    for order in candidates:
        account = _context_from_order(order, target)
        if account is not None:
            logger.info(
                "[Remail] Restored pickup context via email search: %s order=%s",
                target,
                account.order_no or "-",
            )
            return _cache_context(account)

    for order in candidates[:5]:
        order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
        if not order_no:
            continue
        try:
            detail = _unwrap_order(
                _request("GET", f"/v1/open/orders/{quote(order_no, safe='')}")
            )
        except RemailError:
            continue
        account = _context_from_order(detail, target)
        if account is not None:
            logger.info(
                "[Remail] Restored pickup context via order details: %s order=%s",
                target,
                account.order_no or order_no,
            )
            return _cache_context(account)
    return None


def _order_status_error(order: dict) -> str | None:
    status = str(order.get("status") or "").strip().lower()
    if status in _FINAL_ORDER_STATUSES:
        failure = str(order.get("failureCode") or order.get("failure_code") or "").strip()
        return f"Remail order not ready: status={status}" + (f", failure={failure}" if failure else "")
    return None


def _wait_for_order_credentials(order: dict) -> tuple[str, str, str]:
    credentials = _order_credentials(order)
    if credentials:
        return credentials

    order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
    if not order_no:
        raise RemailError("Remail order placed successfully but the response is missing the service token or order number")

    error = _order_status_error(order)
    if error:
        raise RemailError(error)

    deadline = time.monotonic() + _order_wait_seconds()
    latest = order
    while time.monotonic() <= deadline:
        try:
            latest = _unwrap_order(_request("GET", f"/v1/open/orders/{order_no}"))
        except RemailError:
            # The order is created; a transient detail endpoint error must not trigger a new order, keep waiting until the deadline.
            if time.monotonic() >= deadline:
                raise
        else:
            credentials = _order_credentials(latest)
            if credentials:
                return credentials
            error = _order_status_error(latest)
            if error:
                raise RemailError(error)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1, remaining))

    status = str(latest.get("status") or "unknown")
    raise RemailError(f"Remail order timed out waiting for the service token: order={order_no}, status={status}")


def pick_account() -> RemailAccount:
    """Create a Remail code-receiving / long-term purchase order per the config and return the delivered email."""
    project_id = _project_id()
    email_suffix = _email_suffix()
    service_mode = _service_mode()
    supply = _supply_policy()
    idempotency_key = f"turb-gpt-free-register-{uuid.uuid4()}"

    payload = _request(
        "POST",
        "/v1/open/orders",
        params={"serviceMode": service_mode, "supply": supply},
        json_body={"projectId": project_id, "emailSuffix": email_suffix},
        headers={"Idempotency-Key": idempotency_key},
    )
    order = _unwrap_order(payload)
    email, service_token, order_no = _wait_for_order_credentials(order)
    account = RemailAccount(
        email=email,
        service_token=service_token,
        order_no=order_no,
        project_id=project_id,
        email_suffix=email_suffix,
    )
    _cache_context(account)
    logger.info("[Remail] Created email order: %s order=%s project=%s", email, order_no or "-", project_id)
    return account


def get_email() -> str:
    """Legacy entry point compatible with other temporary email clients."""
    return pick_account().email


def get_account_context(email: str) -> RemailAccount | None:
    with _CONTEXT_LOCK:
        return _CONTEXT_CACHE.get(_cache_key(email))


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    """Release the local pickup context; the order lifecycle is managed by the Remail server."""
    with _CONTEXT_LOCK:
        account = _CONTEXT_CACHE.pop(_cache_key(email), None)
    if account:
        logger.info(
            "[Remail] Released pickup context: %s order=%s status=%s note=%s",
            email,
            account.order_no or "-",
            status,
            note or "",
        )


def _parse_timestamp(raw) -> float | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
        return value / 1000.0 if value > 10_000_000_000 else value

    text = str(raw).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        value = float(text)
        return value / 1000.0 if value > 10_000_000_000 else value
    try:
        iso = text[:-1] + "+00:00" if text.endswith("Z") else text
        parsed = datetime.fromisoformat(iso)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _pickup_items(payload) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict):
        payload = data
    elif isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    items = payload.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _message_code(message: dict) -> str | None:
    direct = _first_value(message, "verificationCode", "verification_code", "code", "otp")
    if direct is not None:
        match = _CODE_RE.search(str(direct))
        if match:
            return match.group(1)

    preview = str(_first_value(message, "bodyPreview", "body_preview", "body", "text", "content") or "")
    return extract_otp(
        {
            "from": str(_first_value(message, "sender", "from", "fromEmail") or ""),
            "subject": str(message.get("subject") or ""),
            "text": preview,
            "content": preview,
        }
    )


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """Poll Remail pickup and return the latest six-digit verification code after the claim time."""
    target = str(email or "").strip()
    if not target:
        raise RemailError("Remail code retrieval is missing the email address")
    account = get_account_context(target) or restore_account_context(target)
    if account is None:
        raise RemailError(
            "Remail Cannot find the service token for this email and cannot restore it from the saved order;"
            "make sure the account was registered from Remail, the order can still be picked up, and that you have configured Remail API Key"
        )

    try:
        wait_seconds = int(max_wait if max_wait is not None else getattr(_email_cfg, "OTP_MAX_WAIT", 90))
    except (TypeError, ValueError):
        wait_seconds = 90
    try:
        interval = int(poll_interval if poll_interval is not None else getattr(_email_cfg, "OTP_POLL_INTERVAL", 3))
    except (TypeError, ValueError):
        interval = 3
    try:
        settle = int(settle_seconds if settle_seconds is not None else getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5))
    except (TypeError, ValueError):
        settle = 5
    interval = max(1, interval)
    settle = max(0, settle)
    deadline = time.monotonic() + max(0, wait_seconds)
    best_otp: str | None = None
    best_timestamp = float("-inf")
    settle_until: float | None = None
    last_error = "Inbox is empty or no new verification code has appeared yet"

    logger.info("[Remail] Start polling email %s, for at most %ss", target, wait_seconds)
    while time.monotonic() <= deadline:
        try:
            payload = _request(
                "GET",
                "/v1/pickup",
                params={"email": target, "token": account.service_token},
                authenticated=False,
            )
            items = _pickup_items(payload)
            messages = []
            for message in items:
                received_at = _first_value(
                    message, "receivedAt", "received_at", "timestamp", "createdAt", "created_at"
                )
                timestamp = _parse_timestamp(received_at)
                if after_ts is not None and timestamp is not None and timestamp < after_ts - 30:
                    continue
                code = _message_code(message)
                if code:
                    messages.append((timestamp, code))

            messages.sort(
                key=lambda value: value[0] if value[0] is not None else float("-inf"),
                reverse=True,
            )
            for timestamp, code in messages:
                candidate_time = float("-inf") if timestamp is None else timestamp
                if (
                    best_otp is None
                    or candidate_time > best_timestamp
                    or (candidate_time == best_timestamp and code != best_otp)
                ):
                    best_otp = code
                    best_timestamp = candidate_time
                    settle_until = time.monotonic() + settle
                    logger.info("[Remail] Locked OTP candidate, waiting %ss for confirmation", settle)

            if best_otp and settle_until is not None and time.monotonic() >= settle_until:
                return best_otp
        except RemailError as exc:
            last_error = str(exc)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    if best_otp:
        return best_otp
    raise RemailError(f"Timed out waiting for Remail verification code: {target}; {last_error}")


def list_projects(*, search: str | None = None, product_type: str | None = "microsoft") -> list[dict]:
    """Query the projects visible to the current API Key, for configuration/diagnostics."""
    params = {"offset": 0, "limit": 100}
    if search:
        params["search"] = str(search).strip()
    if product_type:
        params["productType"] = str(product_type).strip()
    payload = _request("GET", "/v1/open/projects", params=params)
    if isinstance(payload, dict):
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        items = data.get("items") if isinstance(data, dict) else None
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []
