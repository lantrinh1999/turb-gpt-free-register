# -*- coding: utf-8 -*-
"""
Email source dispatch layer.

EMAIL_SOURCE Supports a single source or multiple sources:
    "outlook"
    "cloudflare_domain"   # own domain + QQ IMAP
    "cloudflare"          # Cloudflare Worker temporary email
    "generic_api"
    "imap"
    "gptmail"
    "mailnest"
    "cloudmail"
    "remail"
    "mailcode"           # Domain Email MailCode
    "xigua"
    "outlook,generic_api,mailnest,cloudmail,remail"   # fall back in order
    ["outlook", "generic_api", "mailnest", "cloudmail", "remail", "xigua"]  # list syntax is also supported
"""
import logging
from typing import Iterable

logger = logging.getLogger(__name__)

_VALID_SOURCES = ("outlook", "generic_api", "imap", "cloudflare_domain", "cloudflare", "gptmail", "mailnest", "cloudmail", "remail", "xigua", "mailcode")


def parse_email_sources(value=None) -> list[str]:
    """Parse EMAIL_SOURCE into an ordered source list, deduplicating and filtering empty values."""
    if value is None:
        from config import email as _email_cfg
        value = _email_cfg.EMAIL_SOURCE
    if isinstance(value, str):
        raw = value.replace(";", ",").replace("|", ",").split(",")
    elif isinstance(value, Iterable):
        raw = list(value)
    else:
        raw = [value]

    out: list[str] = []
    for item in raw:
        s = str(item or "").strip().strip('"\'')
        if not s:
            continue
        if s not in _VALID_SOURCES:
            logger.warning(f"[EmailProvider] Unknown email source {s!r}, ignored")
            continue
        if s not in out:
            out.append(s)
    return out or ["outlook"]


def _pick_from_source(source: str) -> str:
    if source == "gptmail":
        from core.gptmail_client import pick_account
        return pick_account().email
    if source == "cloudflare":
        from core.cf_temp_mail_client import pick_account
        return pick_account().email
    if source == "cloudflare_domain":
        from core.qqmail_client import pick_domain_email
        return pick_domain_email()
    if source == "generic_api":
        from core.generic_api_mail_client import pick_account
        return pick_account().email
    if source == "imap":
        from core.imap_mail_client import pick_account
        return pick_account().email
    if source == "mailnest":
        from core.mailnest_client import pick_account
        return pick_account().email
    if source == "cloudmail":
        from core.cloudmail_client import pick_account
        return pick_account().email
    if source == "remail":
        from core.remail_client import pick_account
        return pick_account().email
    if source == "mailcode":
        from core.mailcode_client import pick_account
        return pick_account().email
    if source == "xigua":
        from core.xigua_client import pick_account
        return pick_account().email
    from core.outlook_client import pick_account
    return pick_account().email


def acquire_email() -> str:
    """Claim an email address for registration according to EMAIL_SOURCE; with multiple sources, fall back in order."""
    sources = parse_email_sources()
    last_exc: Exception | None = None
    for source in sources:
        try:
            email = _pick_from_source(source)
            logger.info(f"[EmailProvider] Using email source: {source}, email={email}")
            return email
        except Exception as exc:
            last_exc = exc
            logger.warning(f"[EmailProvider] Source {source} failed to claim an email: {type(exc).__name__}: {exc}")
            continue
    raise RuntimeError(f"All email sources failed to claim an email: {sources}; last={last_exc}")


def acquire_email_from_source(source: str) -> str:
    """Claim an email from the single source specified by the caller, unaffected by the EMAIL_SOURCE fallback order."""
    source = str(source or "").strip().lower()
    if source not in _VALID_SOURCES:
        raise ValueError(f"Unsupported email source: {source}")
    email = _pick_from_source(source)
    logger.info("[EmailProvider] Claiming email from the specified source: source=%s, email=%s", source, email)
    return email


def acquire_email_after_input(email: str | None = None) -> str:
    """Claim an email after the browser has found the email input box.

    The browser driver splits finding the input box and claiming the email into two phases, to avoid consuming an email prematurely when page loading, risk control
    or entry detection fails. When an existing email is passed in it is not claimed again, staying compatible with the fixed-email mode.
    """
    current = str(email or "").strip()
    if current:
        return current

    from config import email as _email_cfg

    if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
        raise RuntimeError("The page found the email input box, but auto email claiming is disabled and no value is configured for REGISTER_EMAIL")
    allocated = str(acquire_email() or "").strip()
    if not allocated:
        raise RuntimeError("The email service returned an empty email address")
    logger.info("[EmailProvider] Email input box found, starting to allocate an email: %s", allocated)
    return allocated


def resolve_email_source(email: str) -> str:
    """Determine the actual source from the email; registered accounts prefer the persisted source."""
    # The email_source of a registered account is the final source at registration time. It must be read first; do not
    # let leftover context from another email pool in the current process, or a changed email pool order, cause the same
    # address to be misjudged as belonging to another provider.
    registered_source = _registered_email_source(email)
    if registered_source:
        return registered_source

    from core.gptmail_client import get_account_context as get_gptmail_context
    if get_gptmail_context(email):
        return "gptmail"
    from core.cf_temp_mail_client import get_account_context as get_cf_context
    if get_cf_context(email):
        return "cloudflare"
    from core.mailnest_client import get_account_context as get_mailnest_context
    if get_mailnest_context(email):
        return "mailnest"
    from core.cloudmail_client import get_account_context as get_cloudmail_context
    if get_cloudmail_context(email):
        return "cloudmail"
    from core.remail_client import get_account_context as get_remail_context
    if get_remail_context(email):
        return "remail"
    from core.mailcode_client import get_account_context as get_mailcode_context
    if get_mailcode_context(email):
        return "mailcode"
    from core.xigua_client import get_account_context as get_xigua_context
    if get_xigua_context(email):
        return "xigua"

    from core import db
    if db.get_imap_email_by_email(email):
        return "imap"
    if db.get_generic_api_email_by_email(email):
        return "generic_api"
    if db.get_outlook_by_email(email):
        return "outlook"
    if db._find_domain_email(db._load_domain_pool(), email):  # Internal lightweight query, used only by this project
        return "cloudflare_domain"
    # Fallback: if the domain matches EMAIL_DOMAIN, treat it as a domain email
    try:
        from config import email as _email_cfg
        domain = (_email_cfg.EMAIL_DOMAIN or "").lower().strip()
        if domain and domain != "-" and email.lower().endswith("@" + domain):
            return "cloudflare_domain"
    except Exception:
        pass
    return parse_email_sources()[0]


def _normalize_explicit_email_source(value: str | None) -> str | None:
    """Normalize the email source explicitly specified by the caller.

    The ``email_source`` of a registered account is the single source persisted at registration; liveness checks should prefer
    this value instead of guessing again from the temporary email context of the current process or the global EMAIL_SOURCE.
    Comma/semicolon-separated values occasionally saved in historical data are also supported here; the first valid source is used.
    """
    if value is None:
        return None
    raw = str(value or "").strip()
    if not raw:
        return None
    for item in raw.replace(";", ",").replace("|", ",").split(","):
        source = str(item or "").strip().strip("\"'").lower()
        if source in _VALID_SOURCES:
            return source
    return None


def _registered_email_source(email: str) -> str | None:
    """Read the persisted email source of a registered account."""
    try:
        from core import db

        account = db.get_account_by_email(email)
    except Exception:
        return None
    return _normalize_explicit_email_source((account or {}).get("email_source"))


def wait_for_otp(
    email: str,
    after_ts: float,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    email_source: str | None = None,
    force_service: bool = False,
) -> str:
    """Wait for and return the latest ChatGPT OTP (6-digit string) for this email.

    USE_EMAIL_SERVICE=False uses the manual verification code channel (WebUI submit / CLI input),
    and no longer requires Outlook clientId/refreshToken.
    """
    try:
        from config import email as _email_cfg
        use_service = bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", True))
    except Exception:
        use_service = True

    if not use_service and not force_service:
        from core.manual_otp import wait_for_manual_otp
        from config import email as _email_cfg
        timeout = int(max_wait if max_wait is not None else (getattr(_email_cfg, "OTP_MAX_WAIT", 180) or 180))
        job_id = None
        try:
            from core import registration_service as svc
            job_id = getattr(svc._THREAD_CTX, "job_id", None)
        except Exception:
            job_id = None
        return wait_for_manual_otp(email, timeout=timeout, job_id=job_id)

    extra_kwargs = {}
    if max_wait is not None:
        extra_kwargs["max_wait"] = max_wait
    if poll_interval is not None:
        extra_kwargs["poll_interval"] = poll_interval
    if settle_seconds is not None:
        extra_kwargs["settle_seconds"] = settle_seconds

    # Liveness checks and similar flows for registered accounts pass in the source saved at registration; even if the caller does not pass it explicitly,
    # the persisted account source is read first here, then the current process context / email pool / global config act as fallbacks.
    source = (
        _normalize_explicit_email_source(email_source)
        or _registered_email_source(email)
        or resolve_email_source(email)
    )
    if source == "gptmail":
        from core.gptmail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "cloudflare":
        from core.cf_temp_mail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "cloudflare_domain":
        from core.qqmail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "generic_api":
        from core.generic_api_mail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "imap":
        from core.imap_mail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "mailnest":
        from core.mailnest_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "cloudmail":
        from core.cloudmail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "remail":
        from core.remail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "mailcode":
        from core.mailcode_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "xigua":
        from core.xigua_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    from core.outlook_client import fetch_latest_otp
    return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)


def email_material_line(email: str, source: str | None = None) -> str:
    """Return the email material row to save after the account email is changed."""
    source = _normalize_explicit_email_source(source) or resolve_email_source(email)
    from core import db
    row = None
    if source == "outlook":
        row = db.get_outlook_by_email(email)
    elif source == "generic_api":
        row = db.get_generic_api_email_by_email(email)
    elif source == "imap":
        row = db.get_imap_email_by_email(email)
    if row:
        return str(row.get("copy_line") or email)
    return str(email or "")


def release_email(email: str, status: str = "available", note: str | None = None) -> str:
    """Reclaim the state according to the actual email source and return the source name."""
    source = resolve_email_source(email)
    if source == "gptmail":
        from core.gptmail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "cloudflare":
        from core.cf_temp_mail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "cloudflare_domain":
        from core.qqmail_client import release_domain_email
        release_domain_email(email, status=status, note=note)
    elif source == "generic_api":
        from core.generic_api_mail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "imap":
        from core.imap_mail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "mailnest":
        from core.mailnest_client import release_account
        release_account(email, status=status, note=note)
    elif source == "cloudmail":
        from core.cloudmail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "remail":
        from core.remail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "mailcode":
        from core.mailcode_client import release_account
        release_account(email, status=status, note=note)
    elif source == "xigua":
        from core.xigua_client import release_account
        release_account(email, status=status, note=note)
    else:
        from core.outlook_client import release_account
        release_account(email, status=status, note=note)
    return source


def release_email_if_unconsumed(email: str, note: str | None = None) -> bool:
    """Reclaim task claims still stuck in used, and never overwrite the registered / judged-dead state."""
    if not (email or "").strip():
        return False

    source = resolve_email_source(email)
    from core import db

    if source == "outlook":
        changed = db.release_unconsumed_outlook(email, note=note)
    elif source == "generic_api":
        changed = db.release_unconsumed_generic_api_email(email, note=note)
    elif source == "imap":
        changed = db.release_unconsumed_imap_email(email, note=note)
    elif source == "cloudflare_domain":
        changed = db.release_unconsumed_domain_email(email, note=note)
    else:
        # Temporary emails do not re-enter the local pool, only the process context is cleaned up; the context is kept when a local account already exists.
        if db.get_account_by_email(email) is not None:
            return False
        release_email(email, status="available", note=note)
        changed = True

    if changed:
        logger.info("[EmailProvider] Reclaimed unused email: source=%s, email=%s", source, email)
    return changed
