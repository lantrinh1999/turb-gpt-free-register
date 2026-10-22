# -*- coding: utf-8 -*-
"""
Code-receiving platform client.

Used by the Codex OAuth "brand new session" flow to pass the OpenAI /phone-verification phone number verification:
    1. acquire_number()       getNumber take a phone number (returns activation ID + number)
    2. wait_for_sms_code()    poll getStatus until the SMS verification code arrives
    3. complete() / cancel()  setStatus mark as completed (6) / cancelled (8)(8)

Currently supported:
    - GrizzlySMS: GET text API, docs https://api.grizzlysms.com
    - SMSBower: GET handler_api compatible API, docs https://smsbower.app/cn/api?page=client
    - L: local JSON management API, docs L_API.md
    - H: local JSON management API, docs H_API.md

Pricing: every number taken and every SMS received is billed, so:
    - if no SMS arrives after taking a number, cancel(8) must be called to release it, to avoid being charged for nothing;
    - after the code is received successfully, complete(6) officially completes the activation.
"""
import json
import logging
import threading
import time
from urllib.parse import urljoin

from curl_cffi.requests import Session as CurlSession

# Note: use `from config import codex` rather than `from config.codex import X`,
# so that after the WebUI calls config.reload_all(), this module reads the latest values through codex.X.
from config import codex as _cfg
from config import IMPERSONATE

logger = logging.getLogger(__name__)

# GrizzlySMS Rule: a number cannot be cancelled within 2 minutes after it is taken (anti-abuse).
# A 5-second buffer is left here, and setStatus=8 is sent once the time is up.
_MIN_CANCEL_DELAY = 125

# Record the number-taking time of every activation_id, for cancel() to decide whether to wait.
# A module-level dict is used instead of changing the return value of acquire_number, to stay backward compatible.
_ACQUIRED_AT: dict[str, float] = {}


class SmsProviderError(RuntimeError):
    """Generic code-receiving platform error."""


class SmsNoNumbersError(SmsProviderError):
    """No numbers available (NO_NUMBERS); try another country or retry later."""


class SmsNoBalanceError(SmsProviderError):
    """Insufficient balance (NO_BALANCE); a top-up is required, retrying is pointless - the upper layer should stop immediately."""


class SmsCodeTimeout(SmsProviderError):
    """A single number timed out waiting for an SMS (OpenAI did not send it or it did not arrive)."""


def _http() -> CurlSession:
    s = CurlSession(impersonate=IMPERSONATE)
    s.timeout = _cfg.SMS_REQUEST_TIMEOUT
    return s


def _provider() -> str:
    return str(getattr(_cfg, "SMS_PROVIDER", "grizzly") or "grizzly").strip().lower()


def _request_grizzly(http: CurlSession, params: dict) -> str:
    """
    Send a GrizzlySMS API request and return the response text with whitespace stripped.
    Uniformly recognize common error codes and raise the corresponding exceptions.
    """
    base_params = {"api_key": _cfg.SMS_API_KEY}
    base_params.update(params)
    resp = http.get(_cfg.SMS_API_BASE, params=base_params)
    if resp.status_code != 200:
        raise SmsProviderError(
            f"GrizzlySMS HTTP {resp.status_code}: {(resp.text or '')[:200]}"
        )
    text = (resp.text or "").strip()

    # Common error codes (any action may return them)
    if text == "BAD_KEY":
        raise SmsProviderError("Code-receiving platform API key is invalid (BAD_KEY)")
    if text == "NO_BALANCE":
        raise SmsNoBalanceError("Code-receiving platform has insufficient balance (NO_BALANCE), please top up")
    if text == "NO_NUMBERS":
        raise SmsNoNumbersError("Code-receiving platform has no available numbers (NO_NUMBERS)")
    if text == "SERVICE_UNAVAILABLE_REGION":
        raise SmsProviderError("Code-receiving platform region restricted (SERVICE_UNAVAILABLE_REGION), please switch IP")
    if text in ("BAD_ACTION", "BAD_SERVICE", "BAD_STATUS"):
        raise SmsProviderError(f"Code-receiving platform request parameter error:{text}")
    if text == "NO_ACTIVATION":
        raise SmsProviderError("Activation ID does not exist (NO_ACTIVATION)")
    if text.startswith("The service is prohibited"):
        raise SmsProviderError(f"This service is banned from sale by the platform:{text}")

    return text


def _request_smsbower(http: CurlSession, params: dict) -> str:
    """Send an SMSBower handler_api request and return the response text with whitespace stripped."""
    api_key = str(getattr(_cfg, "SMSBOWER_API_KEY", "") or "").strip()
    if not api_key:
        raise SmsProviderError("SMSBower API Key cannot be empty")
    base = str(getattr(_cfg, "SMSBOWER_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("SMSBOWER_API_BASE cannot be empty")
    resp = http.get(base, params={"api_key": api_key, **params})
    text = (resp.text or "").strip()
    if resp.status_code != 200:
        raise SmsProviderError(f"SMSBower HTTP {resp.status_code}: {text[:200]}")
    if text in ("BAD_KEY", "BAD_ACTION", "BAD_SERVICE", "WRONG_SERVICE", "BAD_STATUS", "NO_ACTIVATION"):
        if text == "BAD_KEY":
            raise SmsProviderError("SMSBower API key is invalid (BAD_KEY)")
        if text in ("BAD_SERVICE", "WRONG_SERVICE"):
            raise SmsProviderError(f"SMSBower Service code is invalid ({text}), for OpenAI/ChatGPT please fill in dr")
        if text == "NO_ACTIVATION":
            raise SmsProviderError("SMSBower Activation ID does not exist (NO_ACTIVATION)")
        raise SmsProviderError(f"SMSBower Request parameter error:{text}")
    if text in ("NO_NUMBERS", "NO_BALANCE", "NO_MONEY"):
        if text in ("NO_BALANCE", "NO_MONEY"):
            raise SmsNoBalanceError(f"SMSBower insufficient balance ({text}), please top up")
        raise SmsNoNumbersError("SMSBower no numbers available (NO_NUMBERS)")
    if text.startswith("The service is prohibited"):
        raise SmsProviderError(f"SMSBower This service is banned from sale:{text}")
    return text


def _smsbower_number_params(service: str | None, country: str | None) -> dict:
    service_code = str(service or _cfg.SMS_SERVICE or "").strip()
    if service_code.lower() in ("openai", "chatgpt"):
        service_code = "dr"
    params = {
        "action": "getNumberV2" if bool(getattr(_cfg, "SMSBOWER_USE_V2", True)) else "getNumber",
        "service": service_code,
        "country": str(country or _cfg.SMS_COUNTRY or "").strip(),
    }
    for key, value in (
        ("maxPrice", getattr(_cfg, "SMS_MAX_PRICE", "")),
        ("minPrice", getattr(_cfg, "SMSBOWER_MIN_PRICE", "")),
        ("providerIds", getattr(_cfg, "SMSBOWER_PROVIDER_IDS", "")),
        ("exceptProviderIds", getattr(_cfg, "SMSBOWER_EXCEPT_PROVIDER_IDS", "")),
        ("phoneException", getattr(_cfg, "SMSBOWER_PHONE_EXCEPTION", "")),
    ):
        value = str(value or "").strip()
        if value:
            params[key] = value
    return params


def _request_smsbower_number(http: CurlSession, params: dict) -> tuple[dict, str]:
    """Take numbers in compatibility order; when the filter has no stock, relax the supplier conditions."""
    candidates: list[dict] = [dict(params)]
    if params.get("action") == "getNumberV2":
        candidates.append({**params, "action": "getNumber"})
    if params.get("providerIds"):
        without_provider = {key: value for key, value in params.items() if key != "providerIds"}
        candidates.append(without_provider)
        if params.get("action") == "getNumberV2":
            candidates.append({**without_provider, "action": "getNumber"})
    unique = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    for index, candidate in enumerate(unique):
        try:
            return candidate, _request_smsbower(http, candidate)
        except SmsNoNumbersError:
            if index + 1 < len(unique):
                logger.warning("[SMSBower] No stock for the number-taking filter, relaxing the conditions and retrying:action=%s providerIds=%s", candidate.get("action"), candidate.get("providerIds", "-"))
                continue
            raise
        except SmsProviderError as exc:
            if candidate.get("action") == "getNumberV2" and "BAD_ACTION" in str(exc) and index + 1 < len(unique):
                logger.warning("[SMSBower] getNumberV2 is not supported by the current API, falling back to the compatible API")
                continue
            raise
    raise SmsProviderError("SMSBower No usable number-taking request plan")


def _l_url(path: str) -> str:
    base = str(getattr(_cfg, "L_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("L_API_BASE cannot be empty")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _l_headers() -> dict:
    token = str(getattr(_cfg, "L_ADMIN_AUTH_CODE", "") or "").strip()
    if not token:
        raise SmsProviderError("L_ADMIN_AUTH_CODE cannot be empty")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_l_json(http: CurlSession, path: str, payload: dict) -> dict:
    resp = http.post(_l_url(path), headers=_l_headers(), data=json.dumps(payload))
    text = (resp.text or "").strip()
    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code != 200:
        msg = data.get("error") if isinstance(data, dict) else ""
        raise SmsProviderError(f"L HTTP {resp.status_code}: {(msg or text)[:200]}")
    if isinstance(data, dict) and data.get("error"):
        error = str(data.get("error") or "")
        raw = str(data.get("raw") or "")
        combined = f"{error} {raw}".strip()
        if "NO_BALANCE" in combined or "余额不足" in combined:
            raise SmsNoBalanceError(f"L insufficient balance (NO_BALANCE):{combined}")
        if "NO_NUMBERS" in combined or "暂无号码" in combined:
            raise SmsNoNumbersError(f"L no numbers available (NO_NUMBERS):{combined}")
        raise SmsProviderError(f"L Request failed:{combined}")
    if not isinstance(data, dict):
        raise SmsProviderError(f"L Response is not a JSON object:{text[:200]}")
    return data


def _h_url(path: str) -> str:
    base = str(getattr(_cfg, "H_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("H_API_BASE cannot be empty")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _h_headers() -> dict:
    token = str(getattr(_cfg, "H_ADMIN_AUTH_CODE", "") or "").strip()
    if not token:
        raise SmsProviderError("H_ADMIN_AUTH_CODE cannot be empty")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_h_json(http: CurlSession, path: str, payload: dict) -> dict:
    resp = http.post(_h_url(path), headers=_h_headers(), data=json.dumps(payload))
    text = (resp.text or "").strip()
    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code != 200:
        msg = data.get("error") if isinstance(data, dict) else ""
        raise SmsProviderError(f"H HTTP {resp.status_code}: {(msg or text)[:200]}")
    if isinstance(data, dict) and data.get("error"):
        error = str(data.get("error") or "")
        raw = str(data.get("raw") or "")
        combined = f"{error} {raw}".strip()
        if "NO_BALANCE" in combined or "余额不足" in combined:
            raise SmsNoBalanceError(f"H insufficient balance (NO_BALANCE):{combined}")
        if "NO_NUMBERS" in combined or "暂无号码" in combined:
            raise SmsNoNumbersError(f"H no numbers available (NO_NUMBERS):{combined}")
        raise SmsProviderError(f"H Request failed:{combined}")
    if not isinstance(data, dict):
        raise SmsProviderError(f"H Response is not a JSON object:{text[:200]}")
    return data


def _release_h_number(activation_id: str, http: CurlSession | None = None) -> dict:
    """Call H_API /api/admin/h/release to release a single number."""
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        raise SmsProviderError("H release missing id")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_h_json(http, "/api/admin/h/release", {"id": activation_id})
        failed = data.get("failed") if isinstance(data, dict) else None
        if isinstance(failed, list) and failed:
            detail = json.dumps(failed, ensure_ascii=False)[:300]
            raise SmsProviderError(f"H release failed id={activation_id}: {detail}")
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        logger.info(f"[SMS:H] Released the number id={activation_id}, released={released}")
        _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def release_h_numbers(ids: list[str], http: CurlSession | None = None) -> dict:
    """Release H numbers in batch."""
    ids = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not ids:
        raise SmsProviderError("H release missing ids")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_h_json(http, "/api/admin/h/release", {"ids": ids})
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        failed = data.get("failed") if isinstance(data, dict) else []
        logger.info(f"[SMS:H] Batch release of numbers completed released={released}, failed={len(failed) if isinstance(failed, list) else 0}")
        for activation_id in ids:
            _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def _release_l_number(activation_id: str, http: CurlSession | None = None) -> dict:
    """Call L_API /api/admin/l/release to release a single number."""
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        raise SmsProviderError("L release missing id")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_l_json(http, "/api/admin/l/release", {"id": activation_id})
        failed = data.get("failed") if isinstance(data, dict) else None
        if isinstance(failed, list) and failed:
            # The API allows partial failures. When releasing a single one, a non-empty failed basically means this id failed to be released.
            detail = json.dumps(failed, ensure_ascii=False)[:300]
            raise SmsProviderError(f"L release failed id={activation_id}: {detail}")
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        logger.info(f"[SMS:L] Released the number id={activation_id}, released={released}")
        _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def release_l_numbers(ids: list[str], http: CurlSession | None = None) -> dict:
    """Release L numbers in batch, reusable by tools / later batch processing."""
    ids = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not ids:
        raise SmsProviderError("L release missing ids")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_l_json(http, "/api/admin/l/release", {"ids": ids})
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        failed = data.get("failed") if isinstance(data, dict) else []
        logger.info(f"[SMS:L] Batch release of numbers completed released={released}, failed={len(failed) if isinstance(failed, list) else 0}")
        for activation_id in ids:
            _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def _normalize_phone_digits(value: str) -> str:
    """Normalize the number fragments returned by the platform / configured into pure digits, to avoid illegal E.164 like +-849..."""
    return "".join(ch for ch in str(value or "").strip() if ch.isdigit())


def _normalize_l_phone(phone: str) -> str:
    phone = _normalize_phone_digits(phone)
    prefix = _normalize_phone_digits(getattr(_cfg, "L_PHONE_PREFIX", ""))
    if prefix and phone and not phone.startswith(prefix):
        return f"{prefix}{phone}"
    return phone


def _normalize_h_phone(phone: str) -> str:
    phone = _normalize_phone_digits(phone)
    prefix = _normalize_phone_digits(getattr(_cfg, "H_PHONE_PREFIX", ""))
    if prefix and phone and not phone.startswith(prefix):
        return f"{prefix}{phone}"
    return phone


def _h_phone_acquire_mode() -> str:
    """
    H Number-taking mode:
      - reusable/reuse/prefer_reuse: prefer reuse, calling /api/admin/h/take-reusable-phone
      - new/fresh/always_new: take a new number each time, calling /api/admin/h/take-phone
    """
    raw = str(getattr(_cfg, "H_PHONE_ACQUIRE_MODE", "reusable") or "reusable").strip().lower()
    if raw in ("new", "fresh", "always_new", "take_phone", "take-phone", "每次取新号", "新号"):
        return "new"
    return "reusable"


# ============================================================
# Take a number
# ============================================================

def acquire_number(
    http: CurlSession | None = None,
    service: str | None = None,
    country: str | None = None,
) -> tuple[str, str]:
    """
    Take a phone number (getNumber).

    Returns:
        (activation_id, phone_number) —— phone_number without the + prefix (e.g. 16195366483)

    Raises:
        SmsNoNumbersError / SmsNoBalanceError / SmsProviderError
    """
    own_http = http is None
    http = http or _http()
    try:
        if _provider() == "smsbower":
            params, text = _request_smsbower_number(http, _smsbower_number_params(service, country))
            if params["action"] == "getNumberV2":
                try:
                    data = json.loads(text)
                except Exception:
                    data = None
                if isinstance(data, dict):
                    activation_id = str(data.get("activationId") or data.get("id") or "").strip()
                    phone = str(data.get("phoneNumber") or data.get("phone") or "").strip()
                    if activation_id and phone:
                        _ACQUIRED_AT[activation_id] = time.time()
                        return activation_id, phone
                raise SmsProviderError(f"SMSBower getNumberV2 Response format error:{text[:200]}")
            if not text.startswith("ACCESS_NUMBER:"):
                raise SmsProviderError(f"SMSBower getNumber Unexpected response:{text[:200]}")
            parts = text.split(":", 2)
            if len(parts) < 3:
                raise SmsProviderError(f"SMSBower getNumber Response format error:{text[:200]}")
            activation_id, phone = parts[1].strip(), parts[2].strip()
            _ACQUIRED_AT[activation_id] = time.time()
            return activation_id, phone

        if _provider() == "l":
            payload = {
                "service": service or _cfg.SMS_SERVICE,
                "country": country or _cfg.SMS_COUNTRY,
            }
            if _cfg.SMS_MAX_PRICE:
                payload["maxPrice"] = _cfg.SMS_MAX_PRICE

            data = _post_l_json(http, "/api/admin/l/take-phone", payload)
            item = data.get("item") or {}
            activation_id = str(item.get("id") or "").strip()
            raw_phone = str(item.get("phone") or "")
            raw_prefix = str(getattr(_cfg, "L_PHONE_PREFIX", "") or "")
            phone = _normalize_l_phone(raw_phone)
            if raw_phone.strip() != phone or raw_prefix.strip():
                logger.info(
                    f"[SMS:L] Number normalization:raw_phone={raw_phone!r}, "
                    f"prefix={raw_prefix!r}, normalized=+{phone}"
                )
            if not activation_id or not phone:
                raise SmsProviderError(f"L take-phone Response lacks item.id/item.phone:{str(data)[:200]}")
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(f"[SMS:L] Number taken successfully:id={activation_id}, phone=+{phone}")
            return activation_id, phone

        if _provider() == "h":
            # H_API Use projectId + country; SMS_SERVICE / SMS_COUNTRY are reused uniformly,
            # to avoid duplicate "service/country" settings between the code-receiving platforms.
            project_id = str(service or _cfg.SMS_SERVICE).strip()
            h_country = str(country or _cfg.SMS_COUNTRY).strip()
            if not project_id:
                raise SmsProviderError("H projectId cannot be empty: please fill in SMS_SERVICE")
            if not h_country:
                raise SmsProviderError("H country cannot be empty: please fill in SMS_COUNTRY")
            payload = {
                "projectId": project_id,
                "country": h_country,
            }
            mode = _h_phone_acquire_mode()
            api_path = "/api/admin/h/take-phone" if mode == "new" else "/api/admin/h/take-reusable-phone"
            data = _post_h_json(http, api_path, payload)
            item = data.get("item") or {}
            activation_id = str(item.get("id") or "").strip()
            raw_phone = str(item.get("phone") or "")
            raw_prefix = str(getattr(_cfg, "H_PHONE_PREFIX", "") or "")
            phone = _normalize_h_phone(raw_phone)
            if raw_phone.strip() != phone or raw_prefix.strip():
                logger.info(
                    f"[SMS:H] Number normalization:raw_phone={raw_phone!r}, "
                    f"prefix={raw_prefix!r}, normalized=+{phone}"
                )
            if not activation_id or not phone:
                raise SmsProviderError(f"H {api_path.rsplit('/', 1)[-1]} Response lacks item.id/item.phone:{str(data)[:200]}")
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(
                f"[SMS:H] Number taken successfully:mode={mode}, api={api_path}, id={activation_id}, phone=+{phone}, "
                f"reused={bool(data.get('reused'))}, duplicate={bool(data.get('duplicate'))}"
            )
            return activation_id, phone

        params = {
            "action": "getNumber",
            "service": service or _cfg.SMS_SERVICE,
            "country": country or _cfg.SMS_COUNTRY,
        }
        if _cfg.SMS_MAX_PRICE:
            params["maxPrice"] = _cfg.SMS_MAX_PRICE

        text = _request_grizzly(http, params)
        # Success format: ACCESS_NUMBER:activation ID:number
        if not text.startswith("ACCESS_NUMBER:"):
            raise SmsProviderError(f"getNumber Unexpected response:{text[:200]}")
        parts = text.split(":")
        if len(parts) < 3:
            raise SmsProviderError(f"getNumber Response format error:{text[:200]}")
        activation_id = parts[1].strip()
        phone = parts[2].strip()
        _ACQUIRED_AT[activation_id] = time.time()
        logger.info(f"[SMS] Number taken successfully:activation_id={activation_id}, phone=+{phone}")
        return activation_id, phone
    finally:
        if own_http:
            http.close()


# ============================================================
# Get the SMS verification code
# ============================================================

def wait_for_sms_code(
    activation_id: str,
    http: CurlSession | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
) -> str:
    """
    Poll getStatus until the SMS verification code is obtained.

    Returns:
        verification code string

    Raises:
        SmsCodeTimeout —— No code received before the timeout (the upper layer can switch numbers and retry)
        SmsProviderError —— the activation was cancelled etc.
    """
    own_http = http is None
    http = http or _http()
    deadline = time.time() + (max_wait or _cfg.SMS_CODE_WAIT)
    interval = poll_interval or _cfg.SMS_POLL_INTERVAL
    try:
        provider = _provider()
        total_wait = max_wait or _cfg.SMS_CODE_WAIT
        logger.info(f"[SMS] Waiting for the SMS verification code activation_id={activation_id}, up to {total_wait}s...")
        round_no = 0
        while time.time() < deadline:
            try:
                from core.registration_service import check_stop_requested
                check_stop_requested()
            except ImportError:
                pass
            round_no += 1
            elapsed = max(0, int(total_wait - max(0, deadline - time.time())))
            remaining_before = max(0, int(deadline - time.time()))
            logger.info(
                f"[SMS] Round {round_no} fetching the verification code activation_id={activation_id},"
                f"waited {elapsed}s, about remaining {remaining_before}s"
            )
            if provider == "l":
                data = _post_l_json(http, "/api/admin/l/fetch-code", {"id": activation_id})
                code = str(data.get("code") or "").strip()
                raw = str(data.get("raw") or "").strip()
                status = str((data.get("item") or {}).get("status") or "").strip()
                if code:
                    logger.info(f"[SMS:L] Round {round_no} received the verification code:{code}")
                    return code
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:L] Round {round_no} did not receive the verification code, status={status or raw or 'WAIT'},"
                    f"{interval}s retrying afterwards (remaining {remaining}s)"
                )
                time.sleep(interval)
                continue

            if provider == "h":
                data = _post_h_json(http, "/api/admin/h/fetch-code", {"id": activation_id})
                code = str(data.get("code") or "").strip()
                raw = str(data.get("raw") or "").strip()
                status = str((data.get("item") or {}).get("status") or "").strip()
                if code:
                    logger.info(f"[SMS:H] Round {round_no} received the verification code:{code}")
                    return code
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:H] Round {round_no} did not receive the verification code, status={status or raw or 'WAIT'},"
                    f"{interval}s retrying afterwards (remaining {remaining}s)"
                )
                time.sleep(interval)
                continue

            if provider == "smsbower":
                text = _request_smsbower(http, {"action": "getStatus", "id": activation_id})
                if text.startswith("STATUS_OK:"):
                    return text.split(":", 1)[1].strip().strip("'")
                if text == "STATUS_CANCEL":
                    raise SmsProviderError("SMSBower Activation was cancelled (STATUS_CANCEL)")
                time.sleep(interval)
                continue

            text = _request_grizzly(http, {"action": "getStatus", "id": activation_id})

            if text.startswith("STATUS_OK:"):
                code = text.split(":", 1)[1].strip()
                logger.info(f"[SMS] Round {round_no} received the verification code:{code}")
                return code
            if text == "STATUS_CANCEL":
                raise SmsProviderError("Activation was cancelled (STATUS_CANCEL)")
            # STATUS_WAIT_CODE / STATUS_WAIT_RETRY:* / STATUS_WAIT_RESEND → keep waiting
            remaining = max(0, int(deadline - time.time()))
            logger.info(f"[SMS] Round {round_no} did not receive the verification code, status={text}, retrying in {interval}s (remaining {remaining}s)")
            time.sleep(interval)

        raise SmsCodeTimeout(f"Timed out waiting for the SMS (>{total_wait}s),activation_id={activation_id}")
    finally:
        if own_http:
            http.close()


# ============================================================
# Change status
# ============================================================

def set_status(activation_id: str, status: int, http: CurlSession | None = None) -> str:
    """
    Set the activation status (setStatus).
        1 = The number is ready (the SMS has been sent)
        3 = Wait for the next SMS (resend)
        6 = complete the activation
        8 = cancel the activation
    """
    own_http = http is None
    http = http or _http()
    try:
        if _provider() == "l":
            logger.debug(f"[SMS:L] Ignored status setting id={activation_id}, status={status}")
            return "OK"
        if _provider() == "smsbower":
            if int(status) == 1:
                return "OK"
            return _request_smsbower(http, {"action": "setStatus", "status": str(status), "id": activation_id})
        return _request_grizzly(http, {"action": "setStatus", "status": str(status), "id": activation_id})
    finally:
        if own_http:
            http.close()


def complete(activation_id: str, http: CurlSession | None = None) -> None:
    """Mark the activation as completed (status=6). A failure only warns and does not raise, to avoid affecting the main flow."""
    if _provider() == "l":
        logger.info(f"[SMS:L] Completed id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "h":
        # H After a successful fetch-code the backend automatically re-fetches according to the multi-receive policy; no release here.
        logger.info(f"[SMS:H] Completed id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "smsbower":
        try:
            set_status(activation_id, 6, http=http)
        except Exception as exc:
            logger.warning(f"[SMSBower] Failed to mark as completed (does not affect the result):{exc}")
        finally:
            _ACQUIRED_AT.pop(activation_id, None)
        return
    try:
        set_status(activation_id, 6, http=http)
        logger.info(f"[SMS] Marked as completed activation_id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
    except Exception as exc:
        logger.warning(f"[SMS] Failed to mark as completed (does not affect the result):{exc}")


def _do_cancel_sync(activation_id: str, http_factory) -> None:
    """Actual synchronous cancel logic: wait out the 2-minute limit -> send the request -> retry once on failure."""
    acquired_at = _ACQUIRED_AT.get(activation_id)
    if acquired_at is not None:
        elapsed = time.time() - acquired_at
        if elapsed < _MIN_CANCEL_DELAY:
            wait = _MIN_CANCEL_DELAY - elapsed
            logger.info(
                f"[SMS] Waiting out the GrizzlySMS 2-minute cancel limit: activation_id={activation_id},"
                f"still need to wait {wait:.0f}s..."
            )
            time.sleep(wait)

    # The background thread must not reuse the external http session (curl_cffi is not thread-safe), so it creates its own
    http = http_factory()
    try:
        for attempt in range(1, 3):
            try:
                set_status(activation_id, 8, http=http)
                logger.info(f"[SMS] Cancelled activation_id={activation_id}")
                _ACQUIRED_AT.pop(activation_id, None)
                return
            except Exception as exc:
                if attempt == 1:
                    logger.warning(f"[SMS] Cancel failed ({exc}), retrying in 5s...")
                    time.sleep(5)
                else:
                    logger.warning(
                        f"[SMS] Cancel finally failed (does not affect the result, cancel manually on the platform):activation_id={activation_id}, {exc}"
                    )
    finally:
        try:
            http.close()
        except Exception:
            pass


def cancel(activation_id: str, http: CurlSession | None = None, background: bool = True) -> None:
    """
    Cancel the activation (status=8), release the number to avoid being charged for nothing.

    GrizzlySMS Rule: a number cannot be cancelled within about 2 minutes after it is taken. This function defaults to background=True,
    putting "wait 2 minutes + cancel" into a background daemon thread, so the main flow returns immediately and continues (e.g. switching to the next number),
    instead of being blocked by those 2 minutes.

    background=False waits out the time synchronously before returning (used in a few scenarios that need to confirm the cancel has completed).

    A failure only warns and does not raise, and does not affect the main flow.
    """
    if _provider() == "l":
        try:
            _release_l_number(activation_id, http=http)
        except Exception as exc:
            logger.warning(f"[SMS:L] Failed to release the number (does not affect the main flow):id={activation_id}, {type(exc).__name__}: {exc}")
            _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "h":
        try:
            _release_h_number(activation_id, http=http)
        except Exception as exc:
            logger.warning(f"[SMS:H] Failed to release the number (does not affect the main flow):id={activation_id}, {type(exc).__name__}: {exc}")
            _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "smsbower":
        try:
            set_status(activation_id, 8, http=http)
        except Exception as exc:
            logger.warning(f"[SMSBower] Failed to release the number (does not affect the main flow):{exc}")
        finally:
            _ACQUIRED_AT.pop(activation_id, None)
        return

    if not background:
        _do_cancel_sync(activation_id, _http)
        return

    t = threading.Thread(
        target=_do_cancel_sync,
        args=(activation_id, _http),
        name=f"sms-cancel-{activation_id}",
        daemon=True,
    )
    t.start()
    logger.debug(f"[SMS] Cancel task dispatched to the background:activation_id={activation_id}")
