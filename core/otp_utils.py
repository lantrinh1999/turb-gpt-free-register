# -*- coding: utf-8 -*-
"""
OTP detection and extraction utilities, used by outlook_client (Outlook mailbox).

Requirements:
    - Multilingual keyword recognition (English / Chinese / Japanese / Korean)
    - Field name tolerance (different mail APIs use different field naming conventions)
    - Context first: among multiple 6-digit numbers, pick the one closest to keywords such as "verification code"
"""
import re

_OPENAI_SENDER_HINT = "openai"

# Multilingual keywords (used to decide whether a message is an OpenAI email)
_OPENAI_KEYWORDS = (
    "chatgpt", "openai",
    # English
    "verification code", "code is", "your code", "verify your email",
    # Chinese
    "代码", "verification code", "确认码",
    # Japanese
    "認証コード", "検証コード", "確認コード", "一時検証", "認証",
    # Korean
    "인증 코드", "확인 코드",
)

# OTP context keywords (used to pick the real verification code among multiple 6-digit numbers)
_OTP_CONTEXT_KEYWORDS = (
    "code", "verify", "verification",
    "代码", "验证", "确认",
    "コード", "認証", "検証", "確認",
    "코드", "인증",
)

_OTP_REGEX = re.compile(r"\b(\d{6})\b")


def _get_field(item: dict, *names: str) -> str:
    """
    Try several possible field names in order from the mail dict, and return the first non-empty string.
    Used for compatibility with the field naming conventions of different mail APIs (e.g. sendEmail / from / fromEmail / from.address).
    """
    for name in names:
        if "." in name:
            # Supports dotted paths such as "from.emailAddress.address"
            value = item
            for part in name.split("."):
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if isinstance(value, str) and value:
                return value
        else:
            value = item.get(name)
            if isinstance(value, str) and value:
                return value
    return ""


def looks_like_openai_email(item: dict) -> bool:
    """
    Decide whether the email comes from OpenAI / ChatGPT. Multilingual, compatible with multiple field names.

    Field name tolerance (different APIs return different styles):
        Sender:  sendEmail / from / fromEmail / from.emailAddress.address
        Sender name:sendName / fromName / from.emailAddress.name
        Plain text:  text / bodyPreview / bodyText
        HTML:    content / body / html / body.content / bodyHtml
    """
    sender = _get_field(item, "sendEmail", "from", "fromEmail", "from.emailAddress.address").lower()
    sender_name = _get_field(item, "sendName", "fromName", "from.emailAddress.name").lower()
    subject = _get_field(item, "subject").lower()
    text = _get_field(item, "text", "bodyPreview", "bodyText").lower()
    content = _get_field(item, "content", "body", "html", "body.content", "bodyHtml").lower()

    if _OPENAI_SENDER_HINT in sender or _OPENAI_SENDER_HINT in sender_name:
        return True

    return any(k in s for s in (subject, text, content) for k in _OPENAI_KEYWORDS)


def extract_otp(item: dict) -> str | None:
    """
    Extract the 6-digit OTP from the email.

    Extraction order:
        1. subject(Some OpenAI emails put the 6-digit number directly in the subject, e.g. "Your OpenAI code is 525210")
        2. Plain text fields (text / bodyPreview / bodyText)
        3. HTML fields (content / html / body / body.content / bodyHtml, after stripping tags)

    If the body contains multiple 6-digit numbers, prefer the one closest to keywords such as "verification code / code / auth".
    """
    # 1. If the subject directly contains a 6-digit number, it is the most trustworthy
    subject = _get_field(item, "subject")
    if subject:
        codes_in_subject = _OTP_REGEX.findall(subject)
        if len(codes_in_subject) == 1:
            # If the subject contains exactly one 6-digit number, it is almost certainly the OTP
            return codes_in_subject[0]

    # 2. body field
    candidates = [
        ("text", _get_field(item, "text", "bodyPreview", "bodyText")),
        ("html", _get_field(item, "content", "html", "body", "body.content", "bodyHtml")),
    ]

    for kind, body in candidates:
        if not body:
            continue
        # Whether text or html, first strip HTML tags and style attributes
        # (For OpenAI emails forwarded by QQ Mail, the text field may also contain HTML)
        body = re.sub(r"<style[^>]*>.*?</style>", " ", body, flags=re.DOTALL | re.IGNORECASE)
        body = re.sub(r"<[^>]+>", " ", body)
        all_codes = _OTP_REGEX.findall(body)
        if not all_codes:
            continue
        body_lower = body.lower()
        # Prefer the 6-digit number closest to a context keyword
        for code in all_codes:
            idx = body_lower.find(code)
            if idx < 0:
                continue
            window = body_lower[max(0, idx - 60): idx + 6 + 60]
            if any(k.lower() in window for k in _OTP_CONTEXT_KEYWORDS):
                return code
        return all_codes[0]
    return None
