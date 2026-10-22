# -*- coding: utf-8 -*-
"""
mail.com email password change module.

Originally depended on the external module mail_password_change (from the chatgpt_mail_register_py project),
now self-implemented and integrated into this project to avoid the external dependency.

Implementation source: change_mailcom_password() in gpt-mail/register_mailcom.py.
Workflow:
    1. Log in to mail.com lightmailer with the current password (establishes session cookies)
    2. Enter the account.mail.com security settings page (log in with the current password if not logged in)
    3. Extract the srttkn token + form action
    4. POST Password change form (currentPassword + newPassword + retypeNewPassword)
    5. After a successful password change, write back to the DB (email_pool.password) + in-memory cache

Just call maybe_change_mailcom_password_before_register(email) before registration:
    - Detect whether the email source is mailcom
    - Read the config.EMAIL_SOURCE / MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER switch
    - Change the password, write back to the DB and cache, return the new password
"""

from __future__ import annotations

import logging
import re
import secrets
import string
from dataclasses import dataclass
from html import unescape
from urllib.parse import quote, urljoin

from bs4 import BeautifulSoup

from core.mailcom_client import (
    MailComError,
    MailComLightClient,
    _CONTEXT_CACHE,
    _http_session,
    _mailcom_proxy,
)

logger = logging.getLogger(__name__)

MAILCOM_ACCOUNT_BASE = "https://account.mail.com"
MAILCOM_ACCOUNT_PASSWORD_PATH = "/ciss/security/edit/passwordChange"
MAILCOM_DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"

PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*_+="
PASSWORD_SYMBOLS = "!@#$%^&*_+="


@dataclass(frozen=True)
class Account:
    """Minimal account structure compatible with the external register_mailcom.Account."""

    username: str
    password: str


# ============================================================
# Password generation
# ============================================================


def generate_mailcom_password(length: int = 12) -> str:
    """Generate a strong password containing upper/lowercase letters, digits, and symbols (12 characters by default).

    Behaves the same as the external register_mailcom.generate_chatgpt_password.
    """
    if length < 12:
        length = 12
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(PASSWORD_SYMBOLS),
    ]
    remaining = [
        secrets.choice(PASSWORD_ALPHABET) for _ in range(length - len(required))
    ]
    chars = required + remaining
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ============================================================
# HTML parsing helpers
# ============================================================


def _extract_form(
    html_text: str, form_id: str | None = None
) -> tuple[str, dict[str, str]]:
    """Extract the action and all input name/value pairs of the specified form from HTML."""
    soup = BeautifulSoup(html_text, "html.parser")
    form = soup.find("form", id=form_id) if form_id else soup.find("form")
    if not form:
        raise MailComError(f"mail.com form not found on page: {form_id or '(first)'}")
    action = form.get("action") or ""
    payload: dict[str, str] = {}
    for input_node in form.find_all("input"):
        name = input_node.get("name")
        if name:
            payload[name] = input_node.get("value", "")
    return action, payload


def _extract_srttkn(*values: str) -> str:
    """Extract the srttkn token from multiple URL / HTML texts."""
    haystack = "\n".join(values)
    patterns = [
        r"[?&]srttkn=([A-Za-z0-9._:-]+)",
        r'name=["\']srttkn["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']srttkn["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, haystack)
        if match:
            return unescape(match.group(1))
    raise MailComError("mail.com passwordChange not found on page srttkn")


def _password_headers(
    referer: str,
    accept_language: str = MAILCOM_DEFAULT_ACCEPT_LANGUAGE,
) -> dict[str, str]:
    """Build the standard headers for accessing the passwordChange page / submitting the form."""
    return {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": accept_language,
        "Cache-Control": "no-cache",
        "Origin": MAILCOM_ACCOUNT_BASE,
        "Pragma": "no-cache",
        "Referer": referer,
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


# ============================================================
# Core of the password change: log in to account.mail.com + submit the passwordChange form
# ============================================================


def ensure_mailcom_account_session(
    client: MailComLightClient, current_password: str
) -> None:
    """Ensure client.session is logged in to account.mail.com (a different domain from lightmailer.mail.com).

    If the page returned by GET account.mail.com/ no longer has a loginForm, consider it logged in and return directly;
    otherwise submit the loginForm with the current password to complete the login.
    """
    session = client.session
    page = session.get(
        f"{MAILCOM_ACCOUNT_BASE}/",
        headers={"Referer": "https://lightmailer.mail.com/settings"},
        timeout=30,
        allow_redirects=True,
    )
    page.raise_for_status()
    html = getattr(page, "text", "") or ""
    if (
        'id="loginForm"' not in html
        and 'name="loginForm"' not in html
        and "/ciss/login" not in getattr(page, "url", "")
    ):
        return

    action, payload = _extract_form(html, "loginForm")
    payload["username"] = client.username
    payload["password"] = current_password
    login = session.post(
        urljoin(getattr(page, "url", MAILCOM_ACCOUNT_BASE), action),
        data=payload,
        headers={
            "Origin": MAILCOM_ACCOUNT_BASE,
            "Referer": getattr(page, "url", MAILCOM_ACCOUNT_BASE),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=30,
        allow_redirects=True,
    )
    login.raise_for_status()
    login_text = getattr(login, "text", "") or ""
    if 'id="loginForm"' in login_text or "login-failed" in getattr(login, "url", ""):
        raise MailComError("mail.com account login failed, cannot enter the password change page")


def change_mailcom_password(
    client: MailComLightClient,
    current_password: str,
    new_password: str,
) -> None:
    """Change the mail.com account password.

    Args:
        client: A MailComLightClient already logged in to lightmailer (client.login() must be called first)
        current_password: current password
        new_password: new password
    """
    session = client.session
    accept_language = str(
        getattr(client, "accept_language", "") or MAILCOM_DEFAULT_ACCEPT_LANGUAGE
    )
    ensure_mailcom_account_session(client, current_password)

    get_url = urljoin(MAILCOM_ACCOUNT_BASE, f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1")
    page = session.get(
        get_url,
        headers=_password_headers(MAILCOM_ACCOUNT_BASE, accept_language),
        timeout=30,
        allow_redirects=True,
    )
    page.raise_for_status()

    token = _extract_srttkn(getattr(page, "url", ""), getattr(page, "text", ""))
    form_action = ""
    try:
        form_action, _ = _extract_form(getattr(page, "text", "") or "", "idb")
    except Exception:
        form_action = ""
    page_url = getattr(page, "url", "") or ""
    referer = (
        page_url
        if "srttkn=" in page_url
        else urljoin(
            MAILCOM_ACCOUNT_BASE,
            f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1&srttkn={quote(token)}",
        )
    )
    if form_action:
        post_url = urljoin(page_url or MAILCOM_ACCOUNT_BASE, form_action)
        if "saveChanges=" not in post_url:
            separator = "&" if "?" in post_url else "?"
            post_url = f"{post_url}{separator}saveChanges=x"
    else:
        post_url = urljoin(
            MAILCOM_ACCOUNT_BASE,
            f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1-1.-form&srttkn={quote(token)}&saveChanges=x",
        )
    payload = {
        "editPanel:username": client.username,
        "editPanel:currentPasswordPanel:topWrapper:inputWrapper:input": current_password,
        "editPanel:newPasswordFieldPanel:topWrapper:inputWrapper:input": new_password,
        "editPanel:retypeNewPasswordFieldPanel:topWrapper:inputWrapper:input": new_password,
    }
    headers = _password_headers(referer, accept_language)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    response = session.post(
        post_url,
        data=payload,
        headers=headers,
        timeout=30,
        allow_redirects=True,
    )
    response.raise_for_status()
    text = getattr(response, "text", "") or ""
    if re.search(
        r"(current password is incorrect|passwords do not match|invalid password|errorMessage)",
        text,
        re.I,
    ):
        raise MailComError("mail.com password change failed, the page returned an error message")


# ============================================================
# Public interface
# ============================================================


def change_account_password(
    account: Account,
    proxy: str = "",
    new_password: str = "",
) -> tuple[Account, str]:
    """Change the mail.com account password.

    Signature-compatible with the external mail_password_change.change_account_password,
    for use by scripts/batch_change_gpt_valid_mails.py / the liveness-check account pool password change.

    Args:
        account: Account(username, password) dataclass
        proxy: Proxy URL; if empty, use _mailcom_proxy()
        new_password: New password; if empty, a random 12-character one is generated

    Returns:
        (account, new_password)
    """
    generated = not bool((new_password or "").strip())
    new_password = (new_password or "").strip() or generate_mailcom_password(12)
    old_password = account.password
    # Before sending the change: explicitly print the old password and the random/specified new password about to be submitted (liveness-check batch password change entry)
    logger.info(
        "[MailCom][Liveness check/batch password change] Before change email=%s old_password=%s "
        "new_password=%s generated=%s (about to send passwordChange)",
        account.username,
        old_password,
        new_password,
        generated,
    )
    proxy = proxy or _mailcom_proxy()
    try:
        client = MailComLightClient(
            account.username,
            account.password,
            session=_http_session(proxy=proxy),
        )
        client.login()
        change_mailcom_password(client, account.password, new_password)
    except Exception as exc:
        logger.error(
            "[MailCom][Liveness check/batch password change] Change failed email=%s old_password=%s "
            "attempted_new_password=%s err=%s",
            account.username,
            old_password,
            new_password,
            exc,
        )
        raise
    logger.info(
        "[MailCom][Liveness check/batch password change] After change email=%s old_password=%s "
        "new_password=%s status=success",
        account.username,
        old_password,
        new_password,
    )
    return account, new_password


def change_mailcom_password_for_email(
    email: str,
    new_password: str = "",
    proxy: str = "",
) -> str:
    """Change the mail.com password by email address and write back to the DB + in-memory cache.

    For the main registration flow / automation tasks: after a successful password change, immediately update email_pool.password and
    mailcom_client._CONTEXT_CACHE, ensuring later wait_for_otp logs in with the new password.

    Args:
        email: mail.com Mailbox Address
        new_password: New password; if empty, a random 12-character one is generated
        proxy: Proxy URL; if empty, use _mailcom_proxy()

    Returns:
        new password
    """
    generated = not bool((new_password or "").strip())
    new_password = (new_password or "").strip() or generate_mailcom_password(12)

    # Get the current account context (in-memory cache → DB fallback)
    from core.mailcom_client import get_account_context

    account_ctx = get_account_context(email)
    if account_ctx is None:
        raise MailComError(
            f"Account context for {email} (mail.com) not found, cannot change the password."
            f"Make sure this email was claimed via pick_account or has been written to the email pool."
        )

    current_password = account_ctx.password
    if not current_password:
        raise MailComError(f"{email} current password is empty, cannot change the password")

    # Before sending the change: first print the pre-change password and the random/specified new password about to be submitted (password change entry before automated registration)
    logger.info(
        "[MailCom][Automated password change] Before change email=%s old_password=%s "
        "new_password=%s generated=%s (about to send passwordChange)",
        email,
        current_password,
        new_password,
        generated,
    )

    # Change password
    _proxy = proxy or _mailcom_proxy()
    try:
        client = MailComLightClient(
            email,
            current_password,
            session=_http_session(proxy=_proxy),
        )
        client.login()
        change_mailcom_password(client, current_password, new_password)
    except Exception as exc:
        logger.error(
            "[MailCom][Automated password change] Change failed email=%s old_password=%s "
            "attempted_new_password=%s err=%s",
            email,
            current_password,
            new_password,
            exc,
        )
        raise
    logger.info(
        "[MailCom][Automated password change] After change email=%s old_password=%s "
        "new_password=%s status=success",
        email,
        current_password,
        new_password,
    )

    # Write back to the in-memory cache; later fetch_latest_otp will use the new password
    from core.mailcom_client import MailComAccount

    _CONTEXT_CACHE[email] = MailComAccount(email=email, password=new_password)

    # Write back to the DB (email_pool.password)
    try:
        from core import db

        db.update_mailcom_email_password(email, new_password)
        logger.info(
            "[MailCom][Automated password change] %s new password written back DB email_pool.password new_password=%s",
            email,
            new_password,
        )
    except Exception as exc:
        logger.warning(
            "[MailCom][Automated password change] %s failed to write the new password back to the DB (does not affect mail retrieval for this registration, cache already updated): %s",
            email,
            exc,
        )

    return new_password


def maybe_change_mailcom_password_before_register(
    email: str,
    new_password: str = "",
) -> str | None:
    """Change the mail.com password before registration when needed.

    Change the password only when all of the following conditions are met:
        1. config.email.MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER is True
        2. email source resolves to mailcom

    Args:
        email: registration email
        new_password: New password; if empty, a random 12-character one is generated

    Returns:
        the new password; if no password change was performed, return None
    """
    try:
        from config import email as _email_cfg
    except Exception:
        return None

    if not bool(getattr(_email_cfg, "MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER", False)):
        return None

    # Determine whether the email source is mailcom
    try:
        from core.email_provider import resolve_email_source

        source = resolve_email_source(email)
    except Exception:
        source = ""
    if source != "mailcom":
        return None

    logger.info(
        "[MailCom][Automated password change] Pre-registration password change triggered, email=%s (will generate/use a random new password and write before/after change logs)",
        email,
    )
    return change_mailcom_password_for_email(email, new_password=new_password)


if __name__ == "__main__":
    # Standalone debugging:python -m core.mail_password_change 'email----password' [new_password]
    import sys as _sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )
    if len(_sys.argv) < 2:
        print(
            "usage: python -m core.mail_password_change 'email----password' [new_password]"
        )
        _sys.exit(2)
    parts = _sys.argv[1].split("----")
    if len(parts) != 2:
        print(f"2 parts format error: got {len(parts)} parts")
        _sys.exit(2)
    _email, _old_pwd = parts
    _new_pwd = _sys.argv[2] if len(_sys.argv) > 2 else ""
    _CONTEXT_CACHE[_email] = Account(username=_email, password=_old_pwd)  # type: ignore[assignment]
    try:
        result = change_mailcom_password_for_email(_email, new_password=_new_pwd)
        print(f"new password: {result}")
    except Exception as ex:
        print(f"ERR: {ex}")
        _sys.exit(1)
