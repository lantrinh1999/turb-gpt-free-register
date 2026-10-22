# -*- coding: utf-8 -*-
"""
Outlook mail client (mail.chatai.codes dual protocol)

Historical account file format (only for first migration / manual compatibility import, one per line):
    # 4 -segment format (basic)
    email----password----clientId----refreshToken
    Example:SorenBarrett5150@outlook.com----oc621409----9e5f94bc-...----M.C529_...
    
    # 6 -segment format (with recovery information)
    email----password----clientId----refreshToken----recoveryEmail----recoveryCode
    Example:ChristinLeno5020@outlook.com----3qP3kEjF----9e5f94bc-...----M.C506_...----Dy9bOAnUd@wmhotmail.com----zf4rBS

Workflow:
    1. pick_account()       Pick an unused account directly from the SQLite email library
    2. fetch_latest_otp()   dual protocol (Graph / IMAP) polling to get the OTP
    3. After a successful registration it is written to the SQLite accounts table

Only use the refresh_token provided by Outlook to call the remote mail.chatai.codes service,
without connecting to Microsoft Graph directly, because the latter needs an access_token + a complex OAuth protocol.
"""
import base64
import email as email_lib
import hashlib
import hmac as hmac_mod
import imaplib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.header import decode_header
from urllib.parse import urlencode
from pathlib import Path

from curl_cffi.requests import Session as CurlSession

from config import (
    OUTLOOK_ACCOUNTS_FILE,
    OUTLOOK_API_BASE,
    OTP_SETTLE_SECONDS,
    USER_AGENT,
    IMPERSONATE,
)
# OTP_POLL_INTERVAL / OTP_MAX_WAIT are hot-changeable in the WebUI, read from the module
from config import email as _email_cfg
from core.otp_utils import looks_like_openai_email, extract_otp

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# In-memory cache of email -> account context, used by fetch_latest_otp
_CONTEXT_CACHE: dict[str, "OutlookAccount"] = {}

# When the remote mail.chatai.codes is disabled, this process skips the remote directly and goes to a direct Microsoft Graph connection.
_REMOTE_DISABLED = False
_MS_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_MS_TOKEN_FATAL_CACHE: dict[str, tuple[str, float]] = {}


@dataclass
class OutlookAccount:
    email: str
    password: str
    client_id: str
    refresh_token: str
    recovery_email: str = ""  # optional: recovery email
    recovery_code: str = ""   # optional: recovery code


class OutlookClientError(RuntimeError):
    """Outlook email service related exceptions."""


def _cache_key(email: str) -> str:
    """Generate the email context cache key, uniformly handled with whitespace stripped / lowercased."""
    return str(email or "").strip().lower()


def _http_session() -> CurlSession:
    s = CurlSession(impersonate=IMPERSONATE)
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Origin": OUTLOOK_API_BASE.rstrip("/"),
        "Referer": OUTLOOK_API_BASE.rstrip("/") + "/",
        "Accept": "*/*",
    })
    s.timeout = 30
    return s


# ============================================================
# mail.chatai.codes secure signature layer (AES-GCM + HMAC-SHA256)
#
# Flow (corresponds exactly to the front-end JS):
#   1. POST /api/security-session {} → { sessionId, sessionToken, sessionKey, expiresAt }
#   2. Build a secure envelope before every API request:
#      iv(12B) random + nonce(16B) random
#      ciphertext = AES-GCM(key, iv, JSON(payload))   ← key = base64url(sessionKey)
#      signedText = "{sessionId}.{nonce}.{timestamp}.{iv}.{ciphertext}"
#      signature  = HMAC-SHA256(key, signedText)
#   3. send the envelope instead of the original payload
# ============================================================

def _b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_dec(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (0 if pad == 4 else pad))


def _aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-GCM Encrypt and return ciphertext || auth_tag (consistent with WebCrypto behavior)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(iv, plaintext, None)
    except ImportError:
        pass
    # fallback: pycryptodome
    from Crypto.Cipher import AES  # type: ignore
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct + tag


# Module-level secure session cache (thread-safe)
_sec_session: dict | None = None
_sec_session_lock = threading.Lock()


def _get_security_session(http: CurlSession) -> dict:
    """Get or refresh the secure session (reused while valid, renewed automatically when expired)."""
    global _sec_session
    now_ms = int(time.time() * 1000)
    with _sec_session_lock:
        if _sec_session and _sec_session["expiresAtMs"] - now_ms > 60_000:
            return _sec_session
        resp = http.post(
            f"{OUTLOOK_API_BASE.rstrip('/')}/api/security-session",
            headers={"Content-Type": "application/json"},
            data="{}",
        )
        if resp.status_code != 200:
            raise OutlookClientError(
                f"security-session initialization failed HTTP {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        if not data.get("success"):
            raise OutlookClientError(f"security-session Return success=False: {data}")
        import datetime
        expires_ms = int(
            datetime.datetime.fromisoformat(
                data["expiresAt"].replace("Z", "+00:00")
            ).timestamp() * 1000
        )
        _sec_session = {
            "sessionId":    data["sessionId"],
            "sessionToken": data["sessionToken"],
            "sessionKey":   data["sessionKey"],
            "expiresAtMs":  expires_ms,
        }
        logger.debug(f"[Outlook] Secure session refreshed sessionId={data['sessionId'][:8]}…")
        return _sec_session


def _secure_post(http: CurlSession, url: str, payload: dict, retry: int = 0) -> dict:
    """
    Encrypt the request body with AES-GCM + HMAC-SHA256 and send it to mail.chatai.codes,
    returning the parsed JSON dict. On 401/403 the session is refreshed automatically and retried once.
    """
    global _sec_session
    session = _get_security_session(http)
    key = _b64url_dec(session["sessionKey"])

    iv    = os.urandom(12)
    nonce = _b64url_enc(os.urandom(16))
    ts    = int(time.time() * 1000)
    plain = json.dumps(payload, separators=(",", ":")).encode()

    ct_bytes  = _aes_gcm_encrypt(key, iv, plain)
    iv_b64    = _b64url_enc(iv)
    ct_b64    = _b64url_enc(ct_bytes)

    signed_text = f"{session['sessionId']}.{nonce}.{ts}.{iv_b64}.{ct_b64}"
    sig = _b64url_enc(
        hmac_mod.new(key, signed_text.encode(), hashlib.sha256).digest()
    )

    envelope = {
        "secure":       True,
        "sessionId":    session["sessionId"],
        "sessionToken": session["sessionToken"],
        "nonce":        nonce,
        "timestamp":    ts,
        "iv":           iv_b64,
        "ciphertext":   ct_b64,
        "signature":    sig,
    }

    resp = http.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(envelope),
    )

    if resp.status_code in (401, 403) and retry < 1:
        logger.warning(f"[Outlook] {resp.status_code}, retrying after refreshing the secure session...")
        with _sec_session_lock:
            _sec_session = None
        return _secure_post(http, url, payload, retry + 1)

    if resp.status_code != 200:
        raise OutlookClientError(
            f"secure_post {url} HTTP {resp.status_code}: {resp.text[:200]}"
        )
    return resp.json()


# ============================================================
# Account file read/write
# ============================================================

def _parse_accounts_file(path: Path) -> list[OutlookAccount]:
    """Parse accounts from a plain text file, only used by import_to_db."""
    if not path.exists():
        return []
    accounts: list[OutlookAccount] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----")
        # Supports the 4-segment or 6-segment format
        if len(parts) == 4:
            email, password, client_id, refresh_token = (p.strip() for p in parts)
            accounts.append(OutlookAccount(email, password, client_id, refresh_token))
        elif len(parts) == 6:
            email, password, client_id, refresh_token, recovery_email, recovery_code = (p.strip() for p in parts)
            accounts.append(OutlookAccount(email, password, client_id, refresh_token, recovery_email, recovery_code))
        else:
            logger.warning(
                f"[Outlook] {path.name} Line {lineno} has the wrong format (expected 4 or 6 segments, got {len(parts)}), skipped"
            )
            continue
    return accounts


# ============================================================
# Public interface: pick an account / get the OTP (all through the DB)
# ============================================================

def pick_account() -> OutlookAccount:
    """
    Atomically pick an Outlook account with status='available' and mark it 'used' (DB transaction).
    Safe for concurrent multi-threading.
    """
    from core.db import claim_next_outlook, outlook_pool_summary

    row = claim_next_outlook()
    if row is None:
        summary = outlook_pool_summary()
        raise OutlookClientError(
            f"Outlook The account pool has no available account: {summary}. "
            "Please import new emails in the email library of the WebUI."
        )

    account = OutlookAccount(
        email=row["email"],
        password=row["password"],
        client_id=row["client_id"],
        refresh_token=row["refresh_token"],
    )
    _CONTEXT_CACHE[_cache_key(account.email)] = account
    logger.info(f"[Outlook] Selected account: {account.email} (DB id={row['id']})")
    return account


def get_account_context(email: str) -> OutlookAccount | None:
    """Look up the OutlookAccount context by email.

    The email pool record is read first; if the email pool record of a registered account has been cleaned up/migrated, it is restored from the Outlook
    material credentials saved with the account itself. This way, after a restart, liveness checks and Codex Auth can still use
    the Outlook source used at registration to fetch the OTP.
    """
    cache_key = _cache_key(email)
    if not cache_key:
        return None
    if cache_key in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[cache_key]
    from core.db import get_account_by_email, get_outlook_by_email

    pool_row = get_outlook_by_email(email)
    # The source of a registered account is authoritative. Even if a record with the same name remains in the local Outlook pool,
    # an account that actually comes from Remail/another source must not wrongly use Outlook for code retrieval.
    registered = get_account_by_email(email)
    registered_source = str((registered or {}).get("email_source") or "").strip().lower()
    registered_source = registered_source.replace(";", ",").replace("|", ",").split(",", 1)[0].strip()
    if registered_source and registered_source != "outlook":
        return None

    # Normally the email pool record is preferred; when the email pool is cleaned up, migrated, or the record is incomplete,
    # it is completed with the same Outlook material saved with the registered account. On a successful registration insert_account
    # the password/client_id/refresh_token are persisted in the account record.
    row = pool_row or registered
    if row is None:
        return None

    def _first_value(*keys: str) -> str:
        for source_row in (row, registered if row is not registered else None):
            if not source_row:
                continue
            for key in keys:
                value = str(source_row.get(key) or "").strip()
                if value:
                    return value
        return ""

    email_value = _first_value("email") or str(email or "").strip()
    password = _first_value("password")
    client_id = _first_value("client_id", "clientId")
    refresh_token = _first_value("refresh_token", "refreshToken")
    if not (email_value and password and client_id and refresh_token):
        return None
    account = OutlookAccount(
        email=email_value,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
        recovery_email=_first_value("recovery_email"),
        recovery_code=_first_value("recovery_code"),
    )
    _CONTEXT_CACHE[cache_key] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    """Update the Outlook account state according to the registration phase result: retryable goes back to available, consumed is marked failed."""
    from core.db import release_outlook
    release_outlook(email, status=status, note=note)
    _CONTEXT_CACHE.pop(_cache_key(email), None)


def import_outlook_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """Read an account text file and import everything into the DB, returns (added, skipped as existing)."""
    from core.db import import_outlook_accounts
    p = Path(path or OUTLOOK_ACCOUNTS_FILE)
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    accounts = _parse_accounts_file(p)
    records = [
        {"email": a.email, "password": a.password, "client_id": a.client_id, "refresh_token": a.refresh_token}
        for a in accounts
    ]
    return import_outlook_accounts(records)


def import_outlook_from_text(text: str) -> tuple[int, int]:
    """Import a multi-line text directly (for pasting) into the DB."""
    from core.db import import_outlook_accounts
    records = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("====")
        if len(parts) != 4:
            continue
        email, password, client_id, refresh_token = (p.strip() for p in parts)
        records.append({
            "email": email, "password": password,
            "client_id": client_id, "refresh_token": refresh_token,
        })
    return import_outlook_accounts(records)


# ============================================================
# Fetch emails: fall back to IMAP when Graph fails IMAP
# ============================================================


def _outlook_fetch_mode() -> str:
    return str(getattr(_email_cfg, "OUTLOOK_FETCH_MODE", "auto") or "auto").strip().lower()


def _is_remote_disabled_error(exc: Exception | str) -> bool:
    text = str(exc or "")
    return "DEPLOYMENT_DISABLED" in text or "HTTP 402" in text or "Payment required" in text


def _ms_http() -> CurlSession:
    s = CurlSession(impersonate=IMPERSONATE)
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })
    s.timeout = 30
    return s


def _token_looks_jwt(token: str) -> bool:
    return str(token or "").count(".") >= 2


def _ms_token_cache_key(account: OutlookAccount) -> str:
    return f"{account.email}|{account.client_id}|{account.refresh_token[:24]}"


def _is_oauth_fatal_error(text: str) -> bool:
    s = str(text or "")
    return (
        "invalid_grant" in s
        and (
            "AADSTS70000" in s
            or "AADSTS65001" in s
            or "unauthorized or expired" in s
            or "has not consented" in s
        )
    )


def _compact_oauth_error(text: str) -> str:
    s = str(text or "").replace("\\n", " ").strip()
    if "AADSTS70000" in s:
        return "AADSTS70000: refresh_token Not authorized or the authorization has expired, the requested Graph/IMAP mail reading cannot be obtained scope"
    if "AADSTS65001" in s:
        return "AADSTS65001: The current client_id has not been authorized by the user, the resource cannot be accessed"
    return s[:240]


def _ms_token_fatal_reason(account: OutlookAccount) -> str | None:
    key = _ms_token_cache_key(account)
    cached = _MS_TOKEN_FATAL_CACHE.get(key)
    if not cached:
        return None
    reason, expires_at = cached
    if expires_at > time.time():
        return reason
    _MS_TOKEN_FATAL_CACHE.pop(key, None)
    return None


def _decode_email_header(header_value: str | None) -> str:
    if not header_value:
        return ""
    out = []
    for part, charset in decode_header(header_value):
        if isinstance(part, bytes):
            try:
                out.append(part.decode(charset or "utf-8", errors="replace"))
            except Exception:
                out.append(part.decode("utf-8", errors="replace"))
        else:
            out.append(str(part))
    return " ".join(out)


def _get_msg_text(msg) -> str:
    if msg.is_multipart():
        text_parts = []
        html_part = ""
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ctype == "text/plain":
                text_parts.append(text)
            elif ctype == "text/html" and not html_part:
                html_part = text
        return "\n".join(text_parts) if text_parts else html_part

    try:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
    except Exception:
        pass
    return str(msg.get_payload() or "")


def _imap_msg_to_dict(msg) -> dict:
    subject = _decode_email_header(msg.get("Subject") or msg.get("subject") or "")
    from_ = _decode_email_header(msg.get("From") or msg.get("from") or "")
    to_ = _decode_email_header(msg.get("To") or msg.get("to") or "")
    body = _get_msg_text(msg)
    date_raw = msg.get("Date") or msg.get("date") or ""
    ts_str = ""
    if date_raw:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts_str = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            ts_str = str(date_raw)
    return {
        "id": msg.get("Message-ID") or msg.get("Message-Id") or "",
        "subject": subject,
        "from": from_,
        "to": to_,
        "fromEmail": from_,
        "fromName": from_,
        "sendEmail": from_,
        "receivedDateTime": ts_str,
        "date": ts_str,
        "bodyPreview": body,
        "content": body,
        "body": body,
        "html": body,
        "text": body,
    }


def _ms_access_token(
    account: OutlookAccount,
    http: CurlSession | None = None,
    preferred_kind: str | None = None,
) -> tuple[str, str]:
    """Exchange the refresh_token for an access_token that can read mail.

    Returns (token, kind):
      - kind="graph": can access graph.microsoft.com (personal Outlook accounts sometimes return an opaque token that is not necessarily a JWT)
      - kind="outlook": Outlook REST token, can access outlook.office.com/api/v2.0
    """
    preferred_kind = str(preferred_kind or "").strip().lower() or None
    if preferred_kind not in (None, "graph", "outlook"):
        preferred_kind = None
    cache_key = _ms_token_cache_key(account)
    fatal_reason = _ms_token_fatal_reason(account)
    if fatal_reason:
        raise OutlookClientError(f"Microsoft OAuth refresh_token token exchange failed: {fatal_reason}")
    cached = _MS_TOKEN_CACHE.get(cache_key)
    now = time.time()
    if cached and cached[1] - now > 120:
        token_kind, token = cached[0].split(":", 1) if ":" in cached[0] else ("graph", cached[0])
        if preferred_kind is None or token_kind == preferred_kind:
            return token, token_kind

    own_http = http is None
    http = http or _ms_http()
    try:
        attempts = [
            (
                "graph",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                {
                    "client_id": account.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": account.refresh_token,
                    "scope": "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read offline_access",
                },
            ),
            (
                "graph",
                "https://login.microsoftonline.com/common/oauth2/token",
                {
                    "client_id": account.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": account.refresh_token,
                    "resource": "https://graph.microsoft.com",
                },
            ),
            (
                "outlook",
                "https://login.microsoftonline.com/common/oauth2/token",
                {
                    "client_id": account.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": account.refresh_token,
                    "resource": "https://outlook.office.com",
                },
            ),
            (
                "outlook",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                {
                    "client_id": account.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": account.refresh_token,
                    "scope": "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access",
                },
            ),
        ]
        if preferred_kind:
            attempts = [item for item in attempts if item[0] == preferred_kind]
        last_text = ""
        for kind, url, payload in attempts:
            resp = http.post(
                url,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                data=urlencode(payload),
            )
            text = resp.text or ""
            last_text = text[:500]
            data = {}
            try:
                data = resp.json()
            except Exception:
                pass
            if resp.status_code == 200 and isinstance(data, dict) and data.get("access_token"):
                expires_in = int(data.get("expires_in") or 3600)
                token = str(data["access_token"])
                # Microsoft Graph For personal Outlook/MSA accounts an opaque access_token may be returned,
                # not necessarily a JWT; Graph still accepts it. Whether it contains "." must not be used to judge if it is usable.
                _MS_TOKEN_CACHE[cache_key] = (f"{kind}:{token}", now + max(300, expires_in - 60))
                logger.debug("[Outlook] Microsoft token obtained successfully kind=%s jwt=%s", kind, _token_looks_jwt(token))
                return token, kind
        if _is_oauth_fatal_error(last_text):
            reason = _compact_oauth_error(last_text)
            _MS_TOKEN_FATAL_CACHE[cache_key] = (reason, time.time() + 600)
            raise OutlookClientError(f"Microsoft OAuth refresh_token token exchange failed: {reason}")
        raise OutlookClientError(f"Microsoft OAuth refresh_token token exchange failed: {last_text}")
    finally:
        if own_http:
            http.close()


def _live_imap_access_token(account: OutlookAccount, http: CurlSession | None = None) -> str:
    """Refresh the IMAP (New) access_token with the Outlook/Live OAuth endpoint.

    The refresh_token of some purchased Outlook material cannot be exchanged at login.microsoftonline.com
    Graph/IMAP scope, but through login.live.com/oauth20_token.srf without scope
    an IMAP.AccessAsUser.All token can be obtained; many tools call it "IMAP (New)".
    """
    cache_key = _ms_token_cache_key(account) + "|live_imap"
    cached = _MS_TOKEN_CACHE.get(cache_key)
    now = time.time()
    if cached and cached[1] - now > 120:
        token_kind, token = cached[0].split(":", 1) if ":" in cached[0] else ("live_imap", cached[0])
        if token_kind == "live_imap":
            return token

    own_http = http is None
    http = http or _ms_http()
    try:
        resp = http.post(
            "https://login.live.com/oauth20_token.srf",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            data=urlencode({
                "client_id": account.client_id,
                "grant_type": "refresh_token",
                "refresh_token": account.refresh_token,
            }),
        )
        text = resp.text or ""
        data = {}
        try:
            data = resp.json()
        except Exception:
            pass
        token = str((data or {}).get("access_token") or "")
        if resp.status_code == 200 and token:
            expires_in = int((data or {}).get("expires_in") or 3600)
            _MS_TOKEN_CACHE[cache_key] = (f"live_imap:{token}", now + max(300, expires_in - 60))
            scope = str((data or {}).get("scope") or "")
            logger.debug("[Outlook] Live IMAP(New) token obtained successfully scope=%s", scope[:160])
            return token
        raise OutlookClientError(f"Live IMAP(New) refresh_token token exchange failed: {text[:500]}")
    finally:
        if own_http:
            http.close()


def _normalize_ms_message(m: dict) -> dict:
    sender = (((m.get("from") or {}).get("emailAddress") or {}) if isinstance(m.get("from"), dict) else {})
    body = m.get("body") if isinstance(m.get("body"), dict) else {}
    content = body.get("content") if isinstance(body, dict) else ""
    received = m.get("receivedDateTime") or m.get("DateTimeReceived") or m.get("date") or ""
    return {
        "id": m.get("id") or m.get("Id") or "",
        "subject": m.get("subject") or m.get("Subject") or "",
        "from": m.get("from") or m.get("From") or {},
        "fromEmail": sender.get("address") or sender.get("Address") or "",
        "fromName": sender.get("name") or sender.get("Name") or "",
        "receivedDateTime": received,
        "date": received,
        "bodyPreview": m.get("bodyPreview") or m.get("BodyPreview") or "",
        "content": content or "",
        "body": content or "",
        "html": content or "",
    }


def _fetch_graph_messages(http: CurlSession, token: str) -> list[dict]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "Prefer": 'outlook.body-content-type="html"',
    }
    url = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
    params = {
        "$top": "20",
        "$orderby": "receivedDateTime desc",
        "$select": "id,subject,from,receivedDateTime,bodyPreview,body",
    }
    resp = http.get(url, headers=headers, params=params)
    text = resp.text or ""
    if resp.status_code != 200:
        raise OutlookClientError(f"Microsoft Graph messages HTTP {resp.status_code}: {text[:500]}")
    data = resp.json()
    rows = data.get("value") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise OutlookClientError(f"Microsoft Graph response is missing value: {str(data)[:300]}")
    out = [_normalize_ms_message(m) for m in rows if isinstance(m, dict)]
    for item in out:
        item["_fetch_source"] = "graph"
    return out


def _fetch_outlook_rest_messages(http: CurlSession, token: str) -> list[dict]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    url = "https://outlook.office.com/api/v2.0/me/mailfolders/inbox/messages"
    attempts = [
        {
            "$top": "20",
            "$orderby": "ReceivedDateTime desc",
            "$select": "Id,Subject,From,ReceivedDateTime,BodyPreview,Body",
        },
        {
            "$top": "20",
            "$orderby": "DateTimeReceived desc",
            "$select": "Id,Subject,From,DateTimeReceived,BodyPreview,Body",
        },
        {"$top": "20"},
    ]
    last_text = ""
    data = None
    for params in attempts:
        resp = http.get(url, headers=headers, params=params)
        text = resp.text or ""
        last_text = text[:500]
        if resp.status_code == 200:
            data = resp.json()
            break
        # When field names are incompatible, automatically downgrade to the next parameter set.
        if resp.status_code == 400 and ("Could not find a property" in text or "ParseUri" in text):
            logger.debug("[Outlook] Outlook REST parameters incompatible, downgrading and retrying: %s", text[:220])
            continue
        raise OutlookClientError(f"Outlook REST messages HTTP {resp.status_code}: {text[:500]}")
    if data is None:
        raise OutlookClientError(f"Outlook REST messages failed: {last_text}")
    rows = data.get("value") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise OutlookClientError(f"Outlook REST response is missing value: {str(data)[:300]}")
    out = []
    for m in rows:
        if not isinstance(m, dict):
            continue
        # Outlook REST Convert the fields to Graph style; the field capitalization differs between versions.
        from_obj = m.get("From") or m.get("from") if isinstance(m.get("From") or m.get("from"), dict) else {}
        email_addr = from_obj.get("EmailAddress") or from_obj.get("emailAddress") if isinstance(from_obj, dict) else {}
        if not isinstance(email_addr, dict):
            email_addr = {}
        body_obj = m.get("Body") or m.get("body") if isinstance(m.get("Body") or m.get("body"), dict) else {}
        received = m.get("ReceivedDateTime") or m.get("DateTimeReceived") or m.get("receivedDateTime") or ""
        out.append({
            "_fetch_source": "outlook_rest",
            "id": m.get("Id") or m.get("id") or "",
            "subject": m.get("Subject") or m.get("subject") or "",
            "from": {"emailAddress": {"address": email_addr.get("Address") or email_addr.get("address") or "", "name": email_addr.get("Name") or email_addr.get("name") or ""}},
            "fromEmail": email_addr.get("Address") or email_addr.get("address") or "",
            "fromName": email_addr.get("Name") or email_addr.get("name") or "",
            "receivedDateTime": received,
            "date": received,
            "bodyPreview": m.get("BodyPreview") or m.get("bodyPreview") or "",
            "content": body_obj.get("Content") or body_obj.get("content") or "",
            "body": body_obj.get("Content") or body_obj.get("content") or "",
            "html": body_obj.get("Content") or body_obj.get("content") or "",
        })
    logger.debug(f"[Outlook] Outlook REST Got {len(out)} emails via the direct connection")
    return out


def _fetch_imap_direct_messages(account: OutlookAccount) -> list[dict]:
    """Read the latest Outlook Inbox emails via local IMAP XOAUTH2."""
    http = _ms_http()
    mail: imaplib.IMAP4_SSL | None = None
    try:
        try:
            token = _live_imap_access_token(account, http=http)
            token_source = "live_imap_new"
        except Exception as live_exc:
            logger.debug("[Outlook] Live IMAP(New) token failed to obtain, trying Entra IMAP token: %s", str(live_exc)[:220])
            token, _kind = _ms_access_token(account, http=http, preferred_kind="outlook")
            token_source = "entra_outlook"
        auth_string = f"user={account.email}\x01auth=Bearer {token}\x01\x01"
        mail = imaplib.IMAP4_SSL("outlook.office365.com", 993)
        mail.authenticate("XOAUTH2", lambda _challenge: auth_string.encode("utf-8"))
        status, _data = mail.select("INBOX")
        if status != "OK":
            raise OutlookClientError(f"IMAP select INBOX failed: {status}")

        status, msg_ids = mail.search(None, "ALL")
        if status != "OK":
            raise OutlookClientError(f"IMAP search failed: {status}")
        ids = msg_ids[0].split() if msg_ids and msg_ids[0] else []
        if not ids:
            logger.debug("[Outlook] Local IMAP inbox is empty")
            return []

        out = []
        for mid in ids[-20:]:
            status, data = mail.fetch(mid, "(RFC822)")
            if status != "OK" or not data:
                continue
            try:
                raw = data[0][1]
                if not isinstance(raw, (bytes, bytearray)):
                    continue
                msg = email_lib.message_from_bytes(raw)
                item = _imap_msg_to_dict(msg)
                item["_fetch_source"] = "imap_new" if token_source == "live_imap_new" else "imap_entra_outlook"
                out.append(item)
            except Exception as exc:
                logger.debug("[Outlook] Failed to parse the email via local IMAP mid=%s: %s", mid, exc)
        if token_source == "live_imap_new":
            logger.info("[Outlook] Local IMAP(New) direct connection got %s emails", len(out))
        else:
            logger.info("[Outlook] Local IMAP direct connection got %s emails token_source=%s", len(out), token_source)
        return out
    except Exception as exc:
        logger.warning("[Outlook] Local IMAP direct connection failed: %s: %s", type(exc).__name__, exc)
        return []
    finally:
        try:
            if mail is not None:
                mail.logout()
        except Exception:
            pass
        http.close()


def _fetch_via_graph_direct(account: OutlookAccount) -> list[dict]:
    """Read the latest Inbox emails by connecting to the Microsoft API directly; when Graph is incompatible, Outlook REST is used automatically."""
    fatal_reason = _ms_token_fatal_reason(account)
    if fatal_reason:
        logger.debug("[Outlook] Skipping Graph/REST: OAuth is known to be unusable:%s", fatal_reason)
        return []
    http = _ms_http()
    try:
        token, kind = _ms_access_token(account, http=http)
        if kind == "graph":
            try:
                out = _fetch_graph_messages(http, token)
                logger.debug(f"[Outlook] Microsoft Graph Got {len(out)} emails via the direct connection")
                return out
            except Exception as exc:
                logger.warning(f"[Outlook] Microsoft Graph read failed, trying Outlook REST: {type(exc).__name__}: {exc}")
                # Fetch the Outlook REST token again. Note that the Graph token cannot be reused;
                # Graph token its audience is graph.microsoft.com, and using it to request
                # outlook.office.com/api/v2.0 returns 401.
                _MS_TOKEN_CACHE.pop(f"{account.email}|{account.client_id}|{account.refresh_token[:24]}", None)
                token, kind = _ms_access_token(account, http=http, preferred_kind="outlook")
        out = _fetch_outlook_rest_messages(http, token)
        logger.debug(f"[Outlook] Outlook REST Got {len(out)} emails via the direct connection")
        return out
    except Exception as exc:
        logger.warning(f"[Outlook] Microsoft/Outlook direct connection failed: {type(exc).__name__}: {exc}")
        return []
    finally:
        http.close()


def _fetch_via(session: CurlSession, protocol: str, account: OutlookAccount) -> list[dict]:
    """
    Fetch the inbox and return the emails list.

    - remote: mail.chatai.codes /api/fetch-graph|imap
    - direct: Microsoft Graph direct connection
    - auto: Use the remote when available; after the remote returns 402/DEPLOYMENT_DISABLED, connect directly automatically Graph
    """
    global _REMOTE_DISABLED
    mode = _outlook_fetch_mode()

    if mode in ("direct", "graph", "graph_direct", "msgraph"):
        if protocol == "graph":
            return _fetch_via_graph_direct(account)
        if protocol == "imap":
            return _fetch_imap_direct_messages(account)
        return []

    if mode == "auto" and _REMOTE_DISABLED:
        if protocol == "graph":
            return _fetch_via_graph_direct(account)
        if protocol == "imap":
            return _fetch_imap_direct_messages(account)
        return []

    url = f"{OUTLOOK_API_BASE.rstrip('/')}/api/fetch-{protocol}"
    payload = {
        "email":        account.email,
        "clientId":     account.client_id,
        "refreshToken": account.refresh_token,
        "keyword":      "",
        "limit":        10,
        "sender":       "",
    }
    try:
        data = _secure_post(session, url, payload)
    except OutlookClientError as exc:
        logger.warning(f"[Outlook] {protocol} Request failed: {exc}")
        if mode == "auto" and _is_remote_disabled_error(exc):
            _REMOTE_DISABLED = True
            logger.warning("[Outlook] The remote mail retrieval service is disabled, automatically switching to the direct Microsoft Graph mode")
            if protocol == "graph":
                return _fetch_via_graph_direct(account)
        return []
    except Exception as exc:
        logger.warning(f"[Outlook] {protocol} Request error: {type(exc).__name__}: {exc}")
        return []

    if not data.get("success"):
        logger.debug(f"[Outlook] {protocol} success=False: {data.get('error')}")
        return []

    emails = data.get("emails") or []
    source = f"remote_{protocol}"
    for item in emails:
        if isinstance(item, dict):
            item.setdefault("_fetch_source", source)
    logger.debug(f"[Outlook] {protocol} Got {len(emails)} emails source={source}")
    return emails


# settle The mechanism default is now read from config (OTP_SETTLE_SECONDS)
# After the first OTP is caught, wait this many more seconds to see whether a later email arrives.
# When a later one is seen the settle timer is reset; it only returns after settle seconds without new emails.


def fetch_otp_with_account(
    account: OutlookAccount,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    subject_includes: list[str] | None = None,
    subject_excludes: list[str] | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    Fetch the OTP for a directly given OutlookAccount (containing client_id / refresh_token).
    Suitable for scenarios where the account is neither in the DB nor in the in-memory cache (e.g. an external script call).
    """
    _CONTEXT_CACHE[_cache_key(account.email)] = account
    return fetch_latest_otp(
        account.email,
        after_ts=after_ts,
        max_wait=max_wait,
        poll_interval=poll_interval,
        subject_includes=subject_includes,
        subject_excludes=subject_excludes,
        settle_seconds=settle_seconds,
    )


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    subject_includes: list[str] | None = None,
    subject_excludes: list[str] | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    Dual-protocol polling to get the OTP, rules:
        - Try Graph first, fall back to IMAP
        - Merge and deduplicate the emails returned by both sides, sorted by time descending
        - Take the **latest** OpenAI email and extract the OTP
        - **settle mechanism**: after the first one is caught, wait settle_seconds more to see whether a later one arrives,
          and use the latest if so; only return after no new emails. This avoids catching an old OTP that is updated by the server midway.

    Args:
        email: target email
        after_ts: UTC timestamp. Only emails newer than this are considered
        max_wait / poll_interval: By default the value in config is used
        subject_includes / subject_excludes: Optional subject filter
        settle_seconds: How many seconds to wait after the first one is caught to see whether a newer one exists (default 8s)
    """
    account = get_account_context(email)
    if account is None:
        raise OutlookClientError(f"Account context of {email} not found, cannot get OTP")

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else OTP_SETTLE_SECONDS
    session = _http_session()

    logger.info(
        f"[Outlook] Starting to poll the inbox of {email} (mode={_outlook_fetch_mode()}, Graph + IMAP local direct connection, REST as a fallback),"
        f"up to {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s..."
    )

    # settle state machine
    best_otp: str | None = None       # the latest one currently seen OTP
    best_ts: float = 0.0              # its email timestamp
    best_subject: str = ""
    best_protocol: str = ""
    best_source: str = ""
    settle_until: float | None = None # After the first one is caught, only return once this moment is reached
    last_diag_log = 0.0

    while time.time() < deadline:
        # Pull again every round, because there may be new emails, or old emails may appear late due to delay
        all_candidates: list[tuple[str, dict, float, str]] = []
        for protocol in ("graph", "imap"):
            emails = _fetch_via(session, protocol, account)
            for item in emails:
                ts = _parse_email_ts(item) or 0.0
                source = str(item.get("_fetch_source") or protocol) if isinstance(item, dict) else protocol
                all_candidates.append((protocol, item, ts, source))

        # Sorted by time descending, the latest first
        all_candidates.sort(key=lambda x: x[2], reverse=True)

        if all_candidates and not best_otp and time.time() - last_diag_log > 12:
            diag = []
            for protocol, item, ts, source in all_candidates[:5]:
                subject = str(item.get("subject") or "")[:90]
                date = item.get("date") or item.get("receivedDateTime") or ""
                is_openai = looks_like_openai_email(item)
                after_ok = True if after_ts is None else _is_after(item, after_ts)
                otp = extract_otp(item)
                diag.append({
                    "p": source,
                    "date": date,
                    "openai": is_openai,
                    "after": after_ok,
                    "otp": bool(otp),
                    "subject": subject,
                })
            logger.info("[Outlook] Email diagnostics top=%s", diag)
            last_diag_log = time.time()

        # Find the "latest OpenAI email that passed the filter" in this round"
        for protocol, item, ts, source in all_candidates:
            if not looks_like_openai_email(item):
                continue

            subject = (item.get("subject") or "")
            subject_lower = subject.lower()
            if subject_includes and not any(s.lower() in subject_lower for s in subject_includes):
                continue
            if subject_excludes and any(s.lower() in subject_lower for s in subject_excludes):
                continue
            if after_ts is not None and not _is_after(item, after_ts):
                continue

            otp = extract_otp(item)
            if not otp:
                continue

            # A candidate is already locked; if a newly seen one is later, replace it and reset the settle countdown
            if ts > best_ts:
                if best_otp:
                    logger.info(
                        f"[Outlook] Found a later OTP={otp} (ts={item.get('date') or item.get('receivedDateTime')}, source={source}), "
                        f"Replacing the earlier {best_otp}, resetting the settle timer"
                    )
                else:
                    logger.info(
                        f"[Outlook] First lock OTP={otp}, source={source}, ts={item.get('date') or item.get('receivedDateTime')}, "
                        f"subject={subject!r}, Waiting {settle}s to see whether a later email arrives..."
                    )
                best_otp = otp
                best_ts = ts
                best_subject = subject
                best_protocol = protocol
                best_source = source
                settle_until = time.time() + settle
            break  # Only care about the latest one of this round

        # Judge whether it can return
        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[Outlook] settle completed, returning OTP={best_otp}, source={best_source or best_protocol}, protocol={best_protocol}, "
                f"subject={best_subject!r}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp:
            logger.info(
                f"[Outlook] Candidate OTP={best_otp} locked, waiting in settle"
                f"(settle remaining ~{int(settle_until - now)}s, total remaining {remaining}s)..."
            )
        else:
            logger.info(
                f"[Outlook] No qualifying OpenAI email received yet, retrying in {interval}s (remaining {remaining}s)..."
            )
        time.sleep(interval)

    # Timed out but a candidate was already locked (the deadline arrived before settle finished waiting)
    if best_otp:
        logger.warning(
            f"[Outlook] Overall timeout but a candidate exists, returning OTP={best_otp}, source={best_source or best_protocol} (subject={best_subject!r})"
        )
        return best_otp

    raise OutlookClientError(
        f"Timed out waiting for the OTP of {email} (>{max_wait or _email_cfg.OTP_MAX_WAIT}s)."
        f"Possible causes: refresh_token invalid / the email blacklisted by OpenAI / IP risk control not passed."
    )


# Time skew tolerance: keep only a very small tolerance.
# When an OTP is resent the previous old code is often only 10~20 seconds earlier; with a 30-second tolerance the old code of the last round would be mistaken for the new one.
_OTP_CLOCK_SKEW_TOLERANCE = 2


def _parse_email_ts(item: dict) -> float | None:
    """Parse the time field of an email into a UTC timestamp; returns None if it cannot be parsed."""
    import calendar
    raw = (
        item.get("date")
        or item.get("receivedDateTime")
        or item.get("createTime")
        or item.get("receivedAt")
        or ""
    )
    if not raw:
        return None

    formats = (
        "%Y-%m-%dT%H:%M:%SZ",       # Graph: 2026-05-08T02:47:00Z
        "%Y-%m-%dT%H:%M:%S.%fZ",    # Graph with microseconds
        "%Y-%m-%d %H:%M:%S",        # IMAP / custom
        "%a, %d %b %Y %H:%M:%S %z", # RFC 2822 with tz
    )
    for fmt in formats:
        try:
            if fmt.endswith("%z"):
                from datetime import datetime
                return datetime.strptime(raw, fmt).timestamp()
            base_fmt = fmt[: fmt.index("%f") - 1] if "%f" in fmt else fmt
            return float(calendar.timegm(time.strptime(raw[:19] if len(raw) >= 19 else raw, base_fmt)))
        except Exception:
            continue
    return None


def _is_after(item: dict, after_ts: float) -> bool:
    """Judge whether the email time is later than after_ts. The tolerance is only 30 seconds to avoid picking up an old OTP."""
    ts = _parse_email_ts(item)
    if ts is None:
        # Time field missing / cannot be parsed -> let it pass (do not drop the email just because parsing failed)
        return True
    return ts >= after_ts - _OTP_CLOCK_SKEW_TOLERANCE
