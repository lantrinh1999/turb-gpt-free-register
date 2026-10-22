# -*- coding: utf-8 -*-
"""
Generic API code-retrieval email client.

Email pool import format:
    email----code_url

Claim an email at registration; when retrieving the code, GET the code_url directly and extract the 6-digit verification code from the response.
The response can be plain text, HTML or JSON, as long as it contains a 6-digit verification code.
"""
import json
import logging
import re
import time
import base64
import html as html_lib
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, urlunparse, parse_qsl, urlencode

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

_CODE_REGEX = re.compile(r"\b(\d{6})\b")
_CONTEXT_WORDS = ("code", "verify", "verification", "verification code", "代码", "确认码", "認証", "コード")
_CONTEXT_CACHE: dict[str, "GenericApiEmailAccount"] = {}
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ACCOUNTS_FILE = _PROJECT_ROOT / "用于注册的API邮箱.txt"
_YANGYANG_MESSAGES_RE = re.compile(r"/messages/([^/]+)/([^/?#]+)", re.IGNORECASE)
_PUBLIC_INBOX_LINK_RE = re.compile(r"^/i/([^/?#]+)/*$", re.IGNORECASE)
_PUBLIC_INBOX_API_RE = re.compile(
    r"^/api/public/inboxes/([^/?#]+)/latest-code/*$", re.IGNORECASE,
)
_YANGYANG_OPENAI_SUBJECT_HINTS = (
    "temporary chatgpt",
    "chatgpt verification code",
    "chatgpt login code",
    "临时 chatgpt",
    "chatgpt 登录代码",
    "chatgpt verification code",
    "一時的な認証コード",
    "一時ログインコード",
)


class GenericApiMailError(RuntimeError):
    """Generic API code-retrieval email error."""


def _redact_proxy_url(proxy_url: str) -> str:
    """Keep the proxy address and protocol in the logs, but hide the authentication information."""
    raw = str(proxy_url or "").strip()
    if not raw:
        return "direct"
    try:
        parsed = urlparse(raw)
        if not parsed.hostname:
            return "configured-proxy"
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        auth = "***@" if parsed.username or parsed.password else ""
        return f"{parsed.scheme}://{auth}{host}{port}"
    except Exception:
        return "configured-proxy"


def _new_http_session(proxy_url: str = "") -> requests.Session:
    """Create a code-retrieval session that does not inherit the system proxy; when a proxy is passed, both HTTP/HTTPS go through that proxy."""
    session = requests.Session()
    session.trust_env = False
    proxy_url = str(proxy_url or "").strip()
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})
    return session


def _cache_busted_url(url: str, attempt: int) -> str:
    """Add a cache-busting parameter to the code retrieval API, so CDN/reverse proxies do not keep returning the previous verification code."""
    try:
        parsed = urlparse(str(url))
        query = parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("_otp_poll", f"{int(time.time() * 1000)}-{attempt}"))
        return urlunparse(parsed._replace(query=urlencode(query)))
    except Exception:
        return url


@dataclass
class GenericApiEmailAccount:
    email: str
    code_url: str


def _public_inbox_latest_code_url(code_url: str) -> str | None:
    """Convert the public inbox link /i/{token} into /api/public/inboxes/{token}/latest-code."""
    try:
        parsed = urlparse(str(code_url or "").strip())
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    match = _PUBLIC_INBOX_LINK_RE.match(parsed.path or "")
    if not match:
        # A latest-code API address imported directly by the user is also accepted.
        match = _PUBLIC_INBOX_API_RE.match(parsed.path or "")
    if not match:
        return None
    token = unquote(match.group(1)).strip()
    if not token or "/" in token:
        return None
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")
    return f"{origin}/api/public/inboxes/{quote(token, safe='')}/latest-code"


def _public_inbox_page_api_url(code_url: str) -> str | None:
    """Return the inbox list API actually used by the public inbox page."""
    latest_url = _public_inbox_latest_code_url(code_url)
    if not latest_url:
        return None
    return latest_url.rsplit("/latest-code", 1)[0]


def _fetch_public_inbox_page_otp(
    session: requests.Session,
    api_url: str,
    email: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """Extract the verification code from the latest email preview/body, following the inbox API used by the /i/{token} page."""
    resp = session.get(
        api_url,
        headers={**headers, "Accept": "application/json"},
        timeout=20,
        verify=False,
    )
    if resp.status_code != 200:
        logger.debug("[GenericAPI] public inbox Pages API HTTP %s: %s", resp.status_code, (resp.text or "")[:160])
        return None
    try:
        data = resp.json()
    except Exception:
        try:
            data = json.loads(resp.text or "")
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    mailbox = data.get("mailbox") or {}
    actual_email = str(mailbox.get("address") if isinstance(mailbox, dict) else mailbox or "").strip()
    if actual_email and actual_email.lower() != email.lower():
        raise GenericApiMailError(
            f"Public inbox link email mismatch: expected={email}, actual={actual_email}"
        )
    items = [x for x in (data.get("messages") or []) if isinstance(x, dict)]
    items.sort(
        key=lambda x: _parse_generic_api_ts(x.get("receivedAt") or x.get("received_at")) or 0,
        reverse=True,
    )
    origin = api_url.split("/api/public/inboxes/", 1)[0]
    token_path = api_url.split("/api/public/inboxes/", 1)[1].split("?", 1)[0].strip("/")
    for item in items:
        received_at = item.get("receivedAt") or item.get("received_at")
        msg_ts = _parse_generic_api_ts(received_at)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            continue
        raw_codes = item.get("verificationCodes") or item.get("verification_codes") or []
        code = next(
            (m.group(1) for value in raw_codes if (m := _CODE_REGEX.search(str(value)))),
            None,
        )
        subject = str(item.get("subject") or "")
        preview = str(item.get("preview") or "")
        if not code:
            code = _extract_yangyang_openai_code(subject, preview)
        msg_id = str(item.get("id") or "").strip()
        # When it is still not extracted from the page list preview, read the detail API the page uses when clicking an email.
        if not code and msg_id:
            detail_url = (
                f"{origin}/api/public/inboxes/{quote(unquote(token_path), safe='')}"
                f"/messages/{quote(msg_id, safe='')}"
            )
            try:
                detail_resp = session.get(
                    detail_url,
                    headers={**headers, "Accept": "application/json"},
                    timeout=20,
                    verify=False,
                )
                if detail_resp.status_code == 200:
                    detail = detail_resp.json()
                    detail_text = "\n".join([
                        str(detail.get("subject") or subject),
                        str(detail.get("preview") or preview),
                        str(detail.get("textBody") or ""),
                        str(detail.get("htmlBody") or ""),
                    ])
                    code = _extract_yangyang_openai_code(subject, detail_text)
            except Exception as exc:
                logger.debug("[GenericAPI] public inbox Failed to read the email details: %s: %s", type(exc).__name__, exc)
        if code:
            return code, {
                "source": "public_inbox_page",
                "mail_id": msg_id,
                "received_at": received_at,
                "msg_ts": msg_ts,
                "subject": subject,
                "from": item.get("fromAddress") or item.get("sender"),
            }
    return None


def _flatten_json(obj) -> str:
    parts: list[str] = []
    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif x is not None:
            parts.append(str(x))
    walk(obj)
    return "\n".join(parts)


def _decode_data_uri(text: str) -> str:
    """Decode the data:text/html;base64,... body into HTML/text from which an OTP can be extracted."""
    if not isinstance(text, str):
        return ""
    if not text.startswith("data:"):
        return text
    try:
        _meta, payload = text.split(",", 1)
    except ValueError:
        return text
    if ";base64" in _meta.lower():
        try:
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        except Exception:
            return text
    try:
        from urllib.parse import unquote_to_bytes
        return unquote_to_bytes(payload).decode("utf-8", errors="replace")
    except Exception:
        return text


def _extract_code(text: str) -> str | None:
    """Extract the 6-digit OTP from plain text / HTML / JSON text."""
    if not text:
        return None

    # Compatible with JSON: flatten all values first and then extract.
    candidates_text = [_decode_data_uri(text), text]
    try:
        parsed = json.loads(text)
        candidates_text.insert(0, _decode_data_uri(_flatten_json(parsed)))
    except Exception:
        pass

    for body in candidates_text:
        # Reuse the email OTP extraction logic.
        code = extract_otp({"text": body, "content": body, "subject": body[:200]})
        if code:
            return code

        codes = _CODE_REGEX.findall(body)
        if not codes:
            continue
        lower = body.lower()
        for code in codes:
            idx = lower.find(code)
            window = lower[max(0, idx - 80): idx + 86]
            if any(w.lower() in window for w in _CONTEXT_WORDS):
                return code
        return codes[-1]
    return None


def _extract_yangyang_openai_code(subject: str, body: str) -> str | None:
    """
    yangyang OpenAI templates in email details often mix in several 6-digit numbers:
    - 202123 / 353740 such CSS/template numbers
    - The real OTP is near "Your code is / code:", usually the last business 6-digit number in the body
    so the "first context hit" of the generic _extract_code cannot be reused directly.
    """
    body = _decode_data_uri(body or "")
    subject_l = (subject or "").lower()
    text = "\n".join([subject or "", body])

    # Strip style/script to reduce interference from 6-digit numbers such as CSS colors, widths and heights.
    clean = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<script[^>]*>.*?</script>", " ", clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"#[0-9a-fA-F]{6}\b", " ", clean)
    clean = re.sub(r"(?:color|background|border|width|height|font-size|line-height)\s*:\s*[^;\"']+", " ", clean, flags=re.IGNORECASE)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()

    codes = _CODE_REGEX.findall(clean)
    if not codes:
        return None

    # Filter known template noise; keep the other 6-digit candidates.
    noise = {"000000", "202123", "353740"}
    candidates = [c for c in codes if c not in noise]
    if not candidates:
        candidates = codes

    lower = clean.lower()
    patterns = (
        r"(?:code is|code:|verification code is|login code is|your code is)\D{0,80}(\d{6})",
        r"(?:验证码|驗證碼|登录代码|登入代碼|確認コード|認証コード|ログインコード)\D{0,80}(\d{6})",
        r"(\d{6})\D{0,80}(?:code|验证码|驗證碼|確認コード|認証コード)",
    )
    for pat in patterns:
        matches = re.findall(pat, clean, flags=re.IGNORECASE)
        matches = [m for m in matches if m not in noise]
        if matches:
            return matches[-1]

    # OpenAI Temporary code emails: after cleaning the noise, the last business 6-digit number is the most stable.
    if any(h in subject_l for h in _YANGYANG_OPENAI_SUBJECT_HINTS) or "openai" in lower or "chatgpt" in lower:
        return candidates[-1]

    return _extract_code(clean)


def _parse_yangyang_code_url(code_url: str) -> tuple[str, str, str] | None:
    """
    Parse mailbox pages such as yangyang.website:
        /messages/{token}/{email}
    Returns (origin, token, email).
    """
    try:
        parsed = urlparse(code_url)
    except Exception:
        return None
    m = _YANGYANG_MESSAGES_RE.search(parsed.path or "")
    if not m:
        return None
    origin = urlunparse((parsed.scheme or "http", parsed.netloc, "", "", "", ""))
    token = unquote(m.group(1))
    email = unquote(m.group(2))
    if not origin or not token or not email:
        return None
    return origin.rstrip("/"), token, email


def _parse_yangyang_ts(value: str | None) -> float | None:
    if not value:
        return None
    raw = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _parse_generic_api_ts(value) -> float | None:
    """Parse the time fields returned by generic APIs, compatible with ISO8601/Z and common local time formats."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # Numeric timestamps: seconds / milliseconds
    if re.fullmatch(r"\d+(?:\.\d+)?", raw):
        try:
            ts = float(raw)
            return ts / 1000.0 if ts > 10_000_000_000 else ts
        except Exception:
            return None
    # ISO8601: 2026-08-05T01:10:17.000Z
    try:
        iso = raw
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            return dt.timestamp()
        return dt.timestamp()
    except Exception:
        pass
    # Common string formats
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _extract_structured_api_code(text: str, after_ts: float | None = None) -> tuple[str, dict] | None:
    """
    Compatible with code retrieval APIs such as newzoe that return JSON directly:
      {"code":"784207","from":"...","subject":"Your temporary ChatGPT login code","time":"2026-08-05T01:10:17.000Z"}

    If the response has time/date/received_at, old codes are filtered by after_ts, to avoid picking up the cached verification code of the previous time.
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    # Common field priority: code / otp / verification_code; otherwise fall back to extracting from the flattened text.
    raw_code = (
        data.get("code")
        or data.get("otp")
        or data.get("verification_code")
        or data.get("verificationCode")
        or data.get("email_code")
        or data.get("emailCode")
    )
    code = None
    if raw_code is not None:
        m = _CODE_REGEX.search(str(raw_code))
        if m:
            code = m.group(1)
    if not code:
        code = _extract_code(_flatten_json(data))
    if not code:
        return None

    ts_raw = (
        data.get("time")
        or data.get("date")
        or data.get("received_at")
        or data.get("receivedAt")
        or data.get("created_at")
        or data.get("createdAt")
        or data.get("timestamp")
    )
    msg_ts = _parse_generic_api_ts(ts_raw)
    if after_ts and msg_ts and msg_ts + 2 < after_ts:
        logger.debug(
            "[GenericAPI] structured API Skipped the old verification code: code=%s ts=%s after=%s subject=%r",
            code,
            ts_raw,
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
            str(data.get("subject") or "")[:80],
        )
        return None

    return code, {
        "source": "structured_api",
        "received_at": ts_raw,
        "msg_ts": msg_ts,
        "subject": data.get("subject"),
        "from": data.get("from") or data.get("fromAddress") or data.get("sender"),
    }


def _fetch_yangyang_otp(
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """Extract the latest 6-digit verification code from the list API + detail API of the yangyang mailbox page."""
    parsed = _parse_yangyang_code_url(code_url)
    if not parsed:
        return None
    origin, token, email = parsed
    token_q = quote(token, safe="")
    email_q = quote(email, safe="@._+-")
    api_url = f"{origin}/api/messages/{token_q}/{email_q}"

    items: list[dict] = []
    cursor: str | None = None
    # The first page is generally enough; up to 5 pages are conservatively supported.
    for _ in range(5):
        url = api_url if not cursor else f"{api_url}?cursor={quote(str(cursor), safe='')}"
        resp = session.get(url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=False)
        if resp.status_code != 200:
            if resp.status_code == 404:
                # Compatible with implementations such as mail.ai1998.xyz which are also /messages/{token}/{email},
                # but have no /api/messages and embed the emails directly in the HTML page.
                return _fetch_inline_messages_page_otp(
                    session=session,
                    code_url=code_url,
                    headers=headers,
                    after_ts=after_ts,
                )
            logger.debug(f"[GenericAPI] yangyang email list HTTP {resp.status_code}: {resp.text[:160]}")
            return None
        data = resp.json()
        page_items = data.get("items") or []
        if isinstance(page_items, list):
            items.extend([x for x in page_items if isinstance(x, dict)])
        if not data.get("has_more") or not data.get("next_cursor"):
            break
        cursor = str(data.get("next_cursor"))

    # API New emails come first by default; sort by time descending again to pick the latest verification code as far as possible.
    items.sort(key=lambda x: _parse_yangyang_ts(x.get("received_at") or x.get("receivedAt")) or 0, reverse=True)
    for item in items:
        msg_ts_raw = item.get("received_at") or item.get("receivedAt")
        msg_ts = _parse_yangyang_ts(msg_ts_raw)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] yangyang Skipped the old email: id=%s ts=%s after=%s subject=%r",
                item.get("id"), msg_ts_raw, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        msg_id = item.get("id")
        if not msg_id:
            continue
        detail_url = f"{origin}/message/{quote(str(msg_id), safe='')}/{token_q}/{email_q}"
        try:
            detail_resp = session.get(detail_url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=False)
            if detail_resp.status_code != 200:
                continue
            detail = detail_resp.json()
        except Exception as exc:
            logger.debug(f"[GenericAPI] yangyang Failed to read the email details: {type(exc).__name__}: {exc}")
            continue

        raw_body = str(detail.get("body") or "")
        body = _decode_data_uri(raw_body)
        subject = str(detail.get("subject") or item.get("subject") or "")
        text = "\n".join([
            subject,
            str(detail.get("fromAddress") or item.get("from_address") or ""),
            str(detail.get("receivedAt") or item.get("received_at") or ""),
            body,
        ])
        code = _extract_yangyang_openai_code(subject, body)
        if code:
            logger.info(
                f"[GenericAPI] yangyang Extracted from the page OTP={code}, "
                f"mail_id={msg_id}, ts={detail.get('receivedAt') or item.get('received_at')}, subject={subject[:80]!r}"
            )
            return code, {
                "mail_id": msg_id,
                "received_at": detail.get("receivedAt") or item.get("received_at"),
                "subject": subject,
                "msg_ts": msg_ts,
            }
    return None


def _strip_html_fragment(value: str) -> str:
    value = str(value or "")
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html_lib.unescape(value)
    value = re.sub(r"[ \t\r\f\v]+", " ", value)
    value = re.sub(r"\n\s+", "\n", value)
    return value.strip()


def _fetch_inline_messages_page_otp(
    *,
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """Parse /messages pages that have no JSON API and render the email cards directly in HTML."""
    try:
        resp = session.get(
            code_url,
            headers={**headers, "Accept": "text/html,application/xhtml+xml,text/plain,*/*"},
            timeout=20,
            verify=False,
        )
        if resp.status_code != 200:
            logger.debug("[GenericAPI] inline messages Pages HTTP %s: %s", resp.status_code, (resp.text or "")[:160])
            return None
        html = resp.text or ""
    except Exception as exc:
        logger.debug("[GenericAPI] inline messages Page read failed: %s: %s", type(exc).__name__, exc)
        return None

    cards = re.findall(r"<article\b[^>]*class=[\"'][^\"']*mail-card[^\"']*[\"'][^>]*>(.*?)</article>", html, flags=re.DOTALL | re.IGNORECASE)
    # When there is no article, step back and split by details blocks, to tolerate subtle class name changes.
    if not cards:
        cards = re.findall(r"<details\b[^>]*>(.*?)</details>", html, flags=re.DOTALL | re.IGNORECASE)

    items: list[dict] = []
    for idx, card in enumerate(cards):
        subject_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*subject[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        date_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*date[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        from_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*meta[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)
        body_m = re.search(r"<pre\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</pre>", card, flags=re.DOTALL | re.IGNORECASE)
        if not body_m:
            body_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)

        subject = _strip_html_fragment(subject_m.group(1) if subject_m else "")
        received_at = _strip_html_fragment(date_m.group(1) if date_m else "")
        from_addr = _strip_html_fragment(from_m.group(1) if from_m else "")
        body = _strip_html_fragment(body_m.group(1) if body_m else card)
        msg_ts = _parse_yangyang_ts(received_at)
        items.append({
            "mail_id": f"inline-{idx}",
            "subject": subject,
            "received_at": received_at,
            "from": from_addr,
            "body": body,
            "msg_ts": msg_ts or 0.0,
        })

    items.sort(key=lambda x: float(x.get("msg_ts") or 0.0), reverse=True)
    for item in items:
        msg_ts = float(item.get("msg_ts") or 0.0)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] inline messages Skipped the old email: id=%s ts=%s after=%s subject=%r",
                item.get("mail_id"), item.get("received_at"),
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        code = _extract_yangyang_openai_code(str(item.get("subject") or ""), str(item.get("body") or ""))
        if code:
            logger.info(
                "[GenericAPI] inline messages Extracted from the page OTP=%s, mail_id=%s, ts=%s, subject=%r",
                code, item.get("mail_id"), item.get("received_at"), str(item.get("subject") or "")[:80],
            )
            return code, {
                "mail_id": item.get("mail_id"),
                "received_at": item.get("received_at"),
                "subject": item.get("subject"),
                "msg_ts": msg_ts,
            }
    return None


def pick_account() -> GenericApiEmailAccount:
    """Claim an available generic API email directly from the SQLite email library."""
    from core.db import claim_next_generic_api_email, generic_api_email_pool_summary

    row = claim_next_generic_api_email()
    if row is None:
        summary = generic_api_email_pool_summary()
        raise GenericApiMailError(
            f"The generic API email pool has no available account: {summary}. Please import in the WebUI email pool: email----code retrieval URL"
        )
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[account.email] = account
    logger.info(f"[GenericAPI] Selected email: {account.email} (DB id={row.get('id')})")
    return account


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """Import generic API emails from a text file, one per line: email----code_url or email====code_url."""
    from core.db import import_generic_api_emails
    p = Path(path) if path else _ACCOUNTS_FILE
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    if not p.exists():
        return 0, 0
    records = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----") if "----" in line else line.split("====")
        parts = [x.strip() for x in parts]
        if len(parts) < 2:
            continue
        records.append({"email": parts[0], "code_url": parts[1]})
    return import_generic_api_emails(records)


def get_account_context(email: str) -> GenericApiEmailAccount | None:
    if email in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[email]
    from core.db import get_generic_api_email_by_email
    row = get_generic_api_email_by_email(email)
    if row is None:
        return None
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[email] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_generic_api_email
    release_generic_api_email(email, status=status, note=note)
    _CONTEXT_CACHE.pop(email, None)


def _fetch_poll_payload(
    *,
    proxy_url: str,
    poll_url: str,
    email: str,
    headers: dict,
    after_ts: float | None,
    is_yangyang: bool,
    public_inbox_api_url: str | None,
):
    """Run a single code retrieval request, with the network route specified by the caller."""
    session = _new_http_session(proxy_url)
    yy_result = (
        _fetch_yangyang_otp(session, poll_url, headers, after_ts=after_ts)
        if is_yangyang else None
    )
    public_result = (
        _fetch_public_inbox_page_otp(
            session, poll_url, email, headers, after_ts=after_ts,
        )
        if public_inbox_api_url else None
    )
    page_result = yy_result or public_result
    if page_result or is_yangyang or public_inbox_api_url:
        return page_result, yy_result, None, ""
    resp = session.get(poll_url, headers=headers, timeout=20, verify=False)
    return None, None, resp, resp.text or ""


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    Poll the code_url configured for this email until a 6-digit verification code is extracted or the timeout is reached.

    settle Mechanism: after the first verification code is obtained, do not return immediately but keep waiting OTP_SETTLE_SECONDS seconds.
    If the code retrieval address returns a different verification code in the meantime, replace the candidate and reset the settle countdown;
    only return after settle seconds without change, to avoid picking up an old code from the API cache.
    """
    account = get_account_context(email)
    if account is None:
        raise GenericApiMailError(f"The generic API email does not exist or was not imported: {email}")

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": "Mozilla/5.0 (compatible; gpt-register/1.0)",
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
    }
    last_error = ""
    best_otp: str | None = None
    best_seen_at: float = 0.0
    settle_until: float | None = None
    logger.info(
        f"[GenericAPI] Starting to poll the code retrieval address: {email},"
        f"up to {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s"
    )
    is_yangyang = _parse_yangyang_code_url(account.code_url) is not None
    public_inbox_api_url = _public_inbox_page_api_url(account.code_url)
    if public_inbox_api_url:
        logger.info(
            "[GenericAPI] Public inbox page recognized, using the page inbox API: host=%s email=%s",
            urlparse(public_inbox_api_url).netloc,
            email,
        )

    selected_proxy = str(getattr(_email_cfg, "GENERIC_API_PROXY", "") or "").strip()
    routes: list[tuple[str, str]] = []
    if selected_proxy:
        routes.append(("generic_api_local_proxy", selected_proxy))
    routes.append(("direct", ""))
    logger.info(
        "[GenericAPI] HTTP Route: proxy=%s, on network errors%s",
        _redact_proxy_url(selected_proxy),
        "fall back to a direct connection" if selected_proxy else "use a direct connection",
    )

    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            # Do not modify the path-style URL of yangyang; its list API itself returns data by email ID.
            base_poll_url = public_inbox_api_url or account.code_url
            poll_url = base_poll_url if is_yangyang else _cache_busted_url(base_poll_url, attempt)
            route_error: Exception | None = None
            page_result = yy_result = resp = None
            text = ""
            for route_index, (_route_name, route_proxy) in enumerate(routes):
                relay = None
                try:
                    effective_proxy = route_proxy
                    page_result, yy_result, resp, text = _fetch_poll_payload(
                        proxy_url=effective_proxy,
                        poll_url=poll_url,
                        email=email,
                        headers=headers,
                        after_ts=after_ts,
                        is_yangyang=is_yangyang,
                        public_inbox_api_url=public_inbox_api_url,
                    )
                    route_error = None
                    break
                except requests.RequestException as exc:
                    route_error = exc
                    last_error = f"{type(exc).__name__}: {exc}"
                    has_fallback = route_index + 1 < len(routes)
                    logger.warning(
                        "[GenericAPI] Page/API request failed:route=%s %s: %s%s",
                        _redact_proxy_url(route_proxy),
                        type(exc).__name__,
                        exc,
                        ", switching to a direct connection and retrying" if has_fallback else "",
                    )
                finally:
                    if relay is not None:
                        relay.close()
            if route_error is not None:
                raise route_error

            if page_result:
                code, yy_meta = page_result
                result_source = str(yy_meta.get("source") or ("yangyang" if yy_result else "public_inbox_page"))
                now_seen = time.time()
                if not best_otp:
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                    logger.info(
                        f"[GenericAPI] First lock OTP={code}, source={result_source} mail_id={yy_meta.get('mail_id')} ts={yy_meta.get('received_at')}, "
                        f"Waiting {settle}s to see whether the code retrieval API shows an updated verification code..."
                    )
                elif code != best_otp:
                    logger.info(
                        f"[GenericAPI] Found an update OTP={code}, source={result_source} mail_id={yy_meta.get('mail_id')} ts={yy_meta.get('received_at')},"
                        f"Replacing the earlier {best_otp}, resetting the settle timer"
                    )
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                else:
                    logger.debug(f"[GenericAPI] The code retrieval API still returns the candidate OTP={best_otp}")
                resp = None
                text = ""
            else:
                if is_yangyang or public_inbox_api_url:
                    last_error = (
                        "yangyang No new verification code email after after_ts has appeared in the list yet"
                        if is_yangyang else
                        "No new verification code email after after_ts has appeared in the public inbox page yet"
                    )
                    resp = None
                    text = ""
            if resp is None:
                pass
            elif resp.status_code == 200:
                public_payload = None
                if public_inbox_api_url:
                    try:
                        public_payload = json.loads(text)
                    except Exception:
                        public_payload = None
                mailbox = str((public_payload or {}).get("mailbox") or "").strip()
                mailbox_mismatch = bool(mailbox and mailbox.lower() != email.lower())
                if mailbox_mismatch:
                    structured = None
                    last_error = f"latest-code returned email mismatch: expected={email}, actual={mailbox}"
                else:
                    # The receivedAt of such public latest-code services may use an independent server time,
                    # which can differ from the running machine by several hours or even a day. It only returns "the latest one", so here
                    # the time field is only diagnostic information and not a hard filter; candidate updates are still handled by the
                    # code/messageId changes and the settle mechanism.
                    structured = _extract_structured_api_code(
                        text,
                        after_ts=None if public_inbox_api_url else after_ts,
                    )
                structured_meta = structured[1] if structured else {}
                code = structured[0] if structured else _extract_code(text)
                if mailbox_mismatch:
                    code = None
                if code:
                    if (
                        public_inbox_api_url
                        and after_ts
                        and structured_meta.get("msg_ts")
                        and float(structured_meta["msg_ts"]) + 2 < after_ts
                    ):
                        logger.warning(
                            "[GenericAPI] latest-code receivedAt is earlier than the code retrieval baseline,"
                            "continuing with the latest email of the server as the candidate:receivedAt=%s after=%s messageId=%s",
                            structured_meta.get("received_at"),
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                            (public_payload or {}).get("messageId"),
                        )
                    now_seen = time.time()
                    if not best_otp:
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                        if structured_meta:
                            logger.info(
                                f"[GenericAPI] First lock OTP={code}, source=structured_api "
                                f"ts={structured_meta.get('received_at')} subject={str(structured_meta.get('subject') or '')[:80]!r}, "
                                f"Waiting {settle}s to see whether the code retrieval API shows an updated verification code..."
                            )
                        else:
                            logger.info(
                                f"[GenericAPI] First lock OTP={code}, "
                                f"Waiting {settle}s to see whether the code retrieval API shows an updated verification code..."
                            )
                    elif code != best_otp:
                        if structured_meta:
                            logger.info(
                                f"[GenericAPI] Found an update OTP={code}, source=structured_api "
                                f"ts={structured_meta.get('received_at')} subject={str(structured_meta.get('subject') or '')[:80]!r},"
                                f"Replacing the earlier {best_otp}, resetting the settle timer"
                            )
                        else:
                            logger.info(
                                f"[GenericAPI] Found an update OTP={code},"
                                f"Replacing the earlier {best_otp}, resetting the settle timer"
                            )
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                    else:
                        logger.debug(f"[GenericAPI] The code retrieval API still returns the candidate OTP={best_otp}")
                else:
                    if not mailbox_mismatch:
                        if public_inbox_api_url and isinstance(public_payload, dict) and public_payload.get("code") is None:
                            last_error = "latest-code returned code=null, the mailbox has not received a verification code yet"
                        else:
                            last_error = f"HTTP 200 but no 6-digit verification code was extracted, response preview: {text[:160]}"
            else:
                last_error = f"HTTP {resp.status_code}: {text[:160]}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[GenericAPI] settle completed, returning OTP={best_otp}, "
                f"candidate lock time={time.strftime('%H:%M:%S', time.localtime(best_seen_at))}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp and settle_until is not None:
            logger.info(
                f"[GenericAPI] Candidate OTP={best_otp} locked, waiting in settle"
                f"(settle remaining ~{max(0, int(settle_until - now))}s, total remaining {remaining}s)..."
            )
        else:
            logger.info(
                f"[GenericAPI] No verification code obtained from the code retrieval API yet,"
                f"{interval}s retrying afterwards (remaining {remaining}s)..."
            )
        time.sleep(interval)

    if best_otp:
        logger.warning(f"[GenericAPI] Overall timeout but a candidate exists, returning OTP={best_otp}")
        return best_otp

    raise GenericApiMailError(f"Timed out waiting for the generic API verification code: {email}; {last_error}")
