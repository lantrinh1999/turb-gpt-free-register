# -*- coding: utf-8 -*-
"""
QQ Mail IMAP client (Cloudflare domain email mode)

Workflow:
    1. pick_domain_email()    Generate a random@domain domain email and persist it
    2. fetch_latest_otp()     Poll QQ Mail via IMAP to fetch the OTP

Dependencies: Python standard library (imaplib, email, ssl), no new third-party packages.
"""
import imaplib
import email as email_lib
import logging
import random
import string
import time
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path

from config import email as _email_cfg
from core.otp_utils import looks_like_openai_email, extract_otp

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class QQMailClientError(RuntimeError):
    """QQ email service related exceptions."""


# ============================================================
# Email parsing utilities
# ============================================================

def _decode_email_header(header_value: str | None) -> str:
    """Decode email headers (handles encodings such as =?UTF-8?B?...?=)."""
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            try:
                result.append(part.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                result.append(part.decode("utf-8", errors="replace"))
        else:
            result.append(str(part))
    return " ".join(result)


def _parse_email_date(msg) -> float | None:
    """Parse the date from an email.message into a UTC timestamp."""
    date_str = msg.get("Date") or msg.get("date")
    if not date_str:
        return None
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        pass
    try:
        parsed = email_lib.utils.parsedate(date_str)
        if parsed:
            import calendar
            return calendar.timegm(parsed)
    except Exception:
        pass
    return None


def _get_msg_text(msg) -> str:
    """Recursively extract the email body (plain text preferred)."""
    if msg.is_multipart():
        text_parts = []
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue
            if ctype == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
        if text_parts:
            return "\n".join(text_parts)

        # fallback: text/html
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue
            if ctype == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
                except Exception:
                    pass
        return ""

    # not multipart
    try:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
    except Exception:
        pass
    return ""


def _msg_to_dict(msg) -> dict:
    """Convert an email.message into a unified dict (compatible with outlook_client)."""
    subject = _decode_email_header(msg.get("Subject") or msg.get("subject") or "")
    from_ = _decode_email_header(msg.get("From") or msg.get("from") or "")
    to_ = _decode_email_header(msg.get("To") or msg.get("to") or "")
    delivered_to = _decode_email_header(msg.get("Delivered-To") or "")
    original_to = _decode_email_header(msg.get("X-Original-To") or "")
    body_text = _get_msg_text(msg)
    ts = _parse_email_date(msg)
    ts_str = (
        datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if ts else ""
    )
    return {
        "subject": subject,
        "from": from_,
        "to": to_,
        "deliveredTo": delivered_to,
        "xOriginalTo": original_to,
        "sendEmail": from_,
        "text": body_text,
        "bodyPreview": body_text,
        "bodyText": body_text,
        "date": ts_str,
        "receivedDateTime": ts_str,
    }


# ============================================================
# IMAP connection and search
# ============================================================

def _connect_imap() -> imaplib.IMAP4_SSL:
    """Connect to the QQ Mail IMAP server and return the connection object."""
    server = _email_cfg.QQ_IMAP_SERVER
    port = _email_cfg.QQ_IMAP_PORT
    qq_email = _email_cfg.QQ_EMAIL
    password = _email_cfg.QQ_IMAP_PASSWORD

    if not qq_email or not password:
        raise QQMailClientError(
            "QQ Mail IMAP is not configured, please set in config/email.py: QQ_EMAIL and QQ_IMAP_PASSWORD"
        )

    try:
        mail = imaplib.IMAP4_SSL(server, port)
        mail.login(qq_email, password)
        mail.select("INBOX")
        return mail
    except imaplib.IMAP4.error as exc:
        raise QQMailClientError(f"QQ Mail IMAP login failed: {exc}")
    except Exception as exc:
        raise QQMailClientError(f"QQ Mail IMAP connection failed: {exc}")


def _search_messages(mail: imaplib.IMAP4_SSL, after_dt: datetime | None = None) -> list[dict]:
    """Search the inbox for emails after after_dt and return a list of dicts."""
    search_criteria = "ALL"
    if after_dt is not None:
        date_str = after_dt.strftime("%d-%b-%Y")
        search_criteria = f'(SINCE {date_str})'

    status, msg_ids = mail.search(None, search_criteria)
    if status != "OK":
        logger.warning(f"[QQMail] IMAP search failed: {status}")
        return []

    ids = msg_ids[0].split() if msg_ids[0] else []
    if not ids:
        return []

    # Only fetch the latest 15 (prevents the inbox from being too large, and is enough)
    recent_ids = ids[-15:]

    messages = []
    for mid in recent_ids:
        status, data = mail.fetch(mid, "(RFC822)")
        if status != "OK":
            continue
        raw_email = data[0][1]
        try:
            msg = email_lib.message_from_bytes(raw_email)
            item = _msg_to_dict(msg)
            messages.append(item)
        except Exception as exc:
            logger.debug(f"[QQMail] Failed to parse message {mid}: {exc}")
            continue

    return messages


# ============================================================
# Public interface
# ============================================================

def pick_domain_email() -> str:
    """
    Generate a random domain email address and record it in the DB.
    Format: {8 random letters/digits}@{EMAIL_DOMAIN}
    """
    from core.db import claim_next_domain_email

    domain = _email_cfg.EMAIL_DOMAIN
    if not domain:
        raise QQMailClientError(
            "EMAIL_DOMAIN is not configured, please set your Cloudflare domain in config/email.py"
        )

    prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    email = f"{prefix}@{domain}"

    claim_next_domain_email(email)
    logger.info(f"[QQMail] Generated domain email: {email}")
    return email


def release_domain_email(email: str, status: str = "available", note: str | None = None) -> None:
    """Update the domain email state."""
    from core.db import release_domain_email as _release
    _release(email, status=status, note=note)


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    Poll QQ Mail via IMAP for the OTP.

    Each polling cycle:
        1. Connect to QQ Mail IMAP and search for emails after the after_ts point in time
        2. Filter emails whose TO recipient address matches email
        3. Use otp_utils to recognize OpenAI verification code emails and extract the 6-digit OTP
        4. settle mechanism: after catching the first message, wait another OTP_SETTLE_SECONDS seconds,
           and return only once confirmed that no later email exists, to avoid picking up a stale OTP

    Args:
        email: Domain email address used for registration (also used to filter the IMAP TO recipient address)
        after_ts: UTC timestamp; only look at emails newer than this time
        max_wait / poll_interval: By default the value in config is used
    """
    if not after_ts:
        after_ts = time.time()
    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    # 30s clock skew tolerance
    after_dt = datetime.fromtimestamp(after_ts - 30, tz=timezone.utc)

    logger.info(
        f"[QQMail] Start polling the QQ Mail inbox (domain: {email}),"
        f"up to {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s..."
    )

    target_lower = email.lower()

    best_otp: str | None = None
    best_ts: float = 0.0
    best_subject: str = ""
    settle_until: float | None = None

    while time.time() < deadline:
        mail = None
        try:
            mail = _connect_imap()
            messages = _search_messages(mail, after_dt=after_dt)
        except QQMailClientError as exc:
            logger.warning(f"[QQMail] IMAP connection failed: {exc}")
            messages = []
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

        # Sort by time in descending order
        messages.sort(key=lambda m: m.get("date") or "", reverse=True)

        # Find the latest OpenAI email
        for item in messages:
            if not looks_like_openai_email(item):
                continue

            # Must match the recipient address (avoid picking up old codes addressed to other domains)
            to_field = (item.get("to") or "").lower()
            if target_lower not in to_field:
                continue

            subject = item.get("subject") or ""
            otp = extract_otp(item)
            if not otp:
                continue

            # Parse timestamp
            ts = 0.0
            raw_ts = item.get("date") or item.get("receivedDateTime") or ""
            if raw_ts:
                try:
                    ts = (
                        datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        .timestamp()
                    )
                except Exception:
                    ts = 0.0

            if after_ts and ts < after_ts - 30:
                continue

            if ts > best_ts:
                if best_otp:
                    logger.info(
                        f"[QQMail] Found a later OTP={otp} (ts={raw_ts}), "
                        f"Replacing the earlier {best_otp}, resetting the settle timer"
                    )
                else:
                    logger.info(
                        f"[QQMail] First lock OTP={otp}, ts={raw_ts}, "
                        f"subject={subject!r}, Waiting {settle}s to see whether a later email arrives..."
                    )
                best_otp = otp
                best_ts = ts
                best_subject = subject
                settle_until = time.time() + settle
            break  # Only the latest one matters

        # settle check
        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[QQMail] settle completed, returning OTP={best_otp}, subject={best_subject!r}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp:
            logger.info(
                f"[QQMail] Candidate OTP={best_otp} locked, waiting in settle"
                f"(settle remaining ~{int(settle_until - now)}s, total remaining {remaining}s)..."
            )
        else:
            logger.info(
                f"[QQMail] No OpenAI email received yet, retrying in {interval}s ({remaining}s remaining)..."
            )
        time.sleep(interval)

    # Timed out but there is a candidate
    if best_otp:
        logger.warning(
            f"[QQMail] Overall timeout but a candidate exists, returning OTP={best_otp} (subject={best_subject!r})"
        )
        return best_otp

    raise QQMailClientError(
        f"Timed out waiting for the OTP of {email} (>{max_wait or _email_cfg.OTP_MAX_WAIT}s)."
        f"Possible causes: QQ Mail IMAP misconfigured / Cloudflare forwarding not in effect / OpenAI email not delivered."
    )
