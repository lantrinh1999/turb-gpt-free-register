# -*- coding: utf-8 -*-
"""
ChatGPT Protocol registration full flow entry point
Chains 12 steps to complete a ChatGPT account registration automatically
"""
import sys
import argparse
import logging
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Callable

from config import REGISTER_EMAIL, REGISTER_NAME  # These two are generally not changed in the WebUI
# Hot-changeable ones, read through module attributes
from config import twofa as _twofa_cfg
from config import email as _email_cfg
from config import roxybrowser as _roxy_cfg
from config import openai_protocol as _protocol_cfg
from config import register as _register_cfg
from core.session import BrowserSession
from core.chatgpt_auth import get_providers, get_csrf_token, signin_openai
from core.openai_auth import (
    follow_authorize,
    request_sentinel_token,
    build_sentinel_header,
    validate_email_otp,
    send_email_otp,
    network_preflight,
    navigate_about_you,
    navigate_create_account_password,
    navigate_email_otp_send,
    request_password_sentinel_bundle,
    generate_registration_password,
    register_user,
    EmailOtpInvalidError,
    create_account,
)
from core.account_export import (
    follow_oauth_callback,
    fetch_session,
    setup_2fa,
    save_account_data,
    create_batch_archive_dir,
)
from core.email_provider import acquire_email, wait_for_otp
from core.humanize import delay as human_delay
from core.name_samples import random_display_name
from core.profile_utils import generate_random_birthday

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

_FINALIZE_SESSION_MAX_ATTEMPTS = 5
_FINALIZE_SESSION_BACKOFF_BASE = 2.0


def configure_logging(verbose: bool = False) -> None:
    """Configure the CLI logging: concise by default, full step details with --verbose."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    for handler in root.handlers:
        handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    if verbose:
        logging.getLogger("core").setLevel(logging.DEBUG)
        return

    logging.getLogger("core").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def _is_success(result: dict) -> bool:
    """Judge whether a single registration succeeded, centralizing the batch statistics rules."""
    return isinstance(result, dict) and bool(result.get("success"))


def _protocol_registration_fingerprint_seed(email: str) -> str | None:
    """Decide by config whether protocol registration reuses the same-email fingerprint across tasks."""
    if not bool(getattr(_register_cfg, "PROTOCOL_REUSE_FINGERPRINT_BY_EMAIL", False)):
        return None
    identity = str(email or "").strip().lower()
    return f"registration:{identity}" if identity else None


def _finalize_registration_session(
    session: BrowserSession,
    continue_url: str,
    email: str,
    callback_referer: str = "https://auth.openai.com/about-you",
) -> tuple[dict, str]:
    """
    Complete the OAuth callback and fetch the accessToken.

    create_account The return of the create endpoint only means it was accepted; it is truly usable only after chatgpt.com
    the login-state cookie is written and /api/auth/session returns the accessToken.
    """
    if not continue_url:
        raise RuntimeError("create_account The response lacks continue_url, cannot complete the OAuth callback")

    last_exc: Exception | None = None
    for attempt in range(1, _FINALIZE_SESSION_MAX_ATTEMPTS + 1):
        try:
            logger.info(
                f"[login state] Completing the OAuth callback and fetching the Token:{email} "
                f"(attempt {attempt}/{_FINALIZE_SESSION_MAX_ATTEMPTS})"
            )
            follow_oauth_callback(session, continue_url, referer=callback_referer)
            human_delay("post_auth")
            session_info = fetch_session(session)
            access_token = session_info.get("accessToken")
            if not access_token:
                raise RuntimeError("session response is missing accessToken")
            logger.info(f"[login state] Got the accessToken:{email}")
            return session_info, access_token
        except Exception as exc:
            last_exc = exc
            if attempt >= _FINALIZE_SESSION_MAX_ATTEMPTS:
                break
            backoff = _FINALIZE_SESSION_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                f"[login state] Callback or Token fetch failed: {email},"
                f"{type(exc).__name__}: {str(exc)[:180]}, retrying in {backoff:.1f}s"
            )
            time.sleep(backoff)

    raise RuntimeError(
        f"OAuth Callback/Token fetch retries exhausted: {email},"
        f"last error:{type(last_exc).__name__ if last_exc else 'Unknown'}: {last_exc}"
    ) from last_exc


def generate_display_name() -> str:
    """Generate a display name made only of English letters and spaces, matching the registration API limits."""
    return random_display_name()


def prepare_registration_inputs() -> tuple[str | None, str, str]:
    """Prepare the email, display name and birthday needed for one registration according to the CLI rules."""
    email = REGISTER_EMAIL
    name = REGISTER_NAME
    birthday = generate_random_birthday()

    # Email: left empty first in automatic mode; the browser driver claims it after the page finds the email input box,
    # protocol and the driver claims it before run_registration starts authentication.
    if not email:
        if not _email_cfg.USE_EMAIL_SERVICE:
            email = input("Please enter the registration email: ").strip()

    # Display name: generated randomly if not filled in
    # OpenAI Restriction: name_invalid_chars - only letters and spaces are allowed, no digits/punctuation
    if not name:
        if _email_cfg.USE_EMAIL_SERVICE:
            name = generate_display_name()
            logger.debug(f"Automatically generated display name: {name}")
        else:
            name = input("Please enter the display name: ").strip()

    if not name:
        raise RuntimeError("Display name cannot be empty")
    if not email and not _email_cfg.USE_EMAIL_SERVICE:
        raise RuntimeError("Email cannot be empty")

    return email, name, birthday


def run_registration(
    email: str | None,
    name: str,
    birthday: str | None = None,
    proxy: str = None,
    otp_code: str = None,
    batch_dir=None,
    on_email_acquired: Callable[[str], None] | None = None,
):
    """
    Run the complete ChatGPT email-and-password registration flow.

    OpenAI Current default flow: signin carries login_hint+screen_hint=login_or_signup
    → enter /create-account/password and submit the password -> send and verify the email OTP
    → about-you submit nickname and birthday -> done.

    Args:
        email: registration email
        name: user display name
        birthday: birthday, format YYYY-MM-DD
        proxy: Proxy address (when not passed one is drawn from PROXY_POOL at random)
        otp_code: Email verification code (if None, it waits for manual input)
    """
    # Optional registration drivers:
    #   protocol     = Original pure protocol (curl_cffi)
    #   roxy         = RoxyBrowser fingerprint browser + Selenium
    #   cloak        = CloakBrowser + Playwright/Selenium adapter layer
    #   browser_use  = Browser Use Cloud stealth Chromium + Playwright
    #   skyvern      = Skyvern Browser Sessions + Playwright
    driver_mode = str(getattr(_roxy_cfg, "REGISTRATION_DRIVER", "protocol") or "protocol").strip().lower()
    if driver_mode in ("roxy", "roxybrowser", "fingerprint", "browser"):
        from core.roxy_registration import run_roxy_registration
        return run_roxy_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("cloak", "cloakbrowser"):
        from core.cloakbrowser_registration import run_cloak_registration
        return run_cloak_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("browser_use", "browseruse", "browser-use", "bu"):
        from core.browser_use_registration import run_browser_use_registration
        return run_browser_use_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("skyvern", "sv"):
        from core.skyvern_registration import run_skyvern_registration
        return run_skyvern_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode not in ("protocol", "api", "http"):
        raise RuntimeError(
            f"Unsupported REGISTRATION_DRIVER={driver_mode!r}, options are protocol / roxy / cloak / browser_use / skyvern"
        )

    # The pure-protocol driver has no "email input box" to wait for, so the email is claimed before the BrowserSession is created.
    if not str(email or "").strip():
        if not _email_cfg.USE_EMAIL_SERVICE:
            raise RuntimeError(
                "Manual mode has no email configured. Please set REGISTER_EMAIL on the WebUI config page,"
                "or enable USE_EMAIL_SERVICE and claim one from the email pool."
            )
        email = acquire_email()
        if on_email_acquired:
            on_email_acquired(email)

    # Create the browser session (when proxy=None one is drawn from config.PROXY_POOL at random automatically)
    fingerprint_seed = _protocol_registration_fingerprint_seed(email)
    reuse_fingerprint = fingerprint_seed is not None
    # The same fingerprint is always reused within the lifetime of a single BrowserSession; whether it is stably reused across tasks by email
    # is controlled by PROTOCOL_REUSE_FINGERPRINT_BY_EMAIL.
    session = BrowserSession(
        proxy=proxy,
        fingerprint_seed=fingerprint_seed,
    )

    # Extract the sid segment from the proxy URL for logging, to avoid printing the account and password in full
    proxy_label = "none"
    if session.proxy:
        # shaped like socks5h://user-region-JP-sid-XXXX-t-5:pass@host:port
        try:
            sid_part = next(
                (seg for seg in session.proxy.split("@")[0].split("-") if len(seg) == 8),
                "***",
            )
            proxy_label = f"{session.proxy.split('://')[0]}://...sid-{sid_part}...@{session.proxy.split('@')[-1]}"
        except Exception:
            proxy_label = "configured"

    if not birthday:
        birthday = generate_random_birthday()

    logger.info(f"[registration] Start: {email}, proxy={proxy_label}")
    logger.info(
        "[fingerprint] Lifecycle mode:%s",
        "kept per email" if reuse_fingerprint else "re-created per task",
    )
    logger.info(f"[registration] Random birthday this time: {birthday}")
    fp = session.fingerprint_summary()
    logger.info(
        "[fingerprint] Unified context of protocol registration: device_id=%s oai_session_id=%s auth_session_logging_id=%s "
        "ua=%s lang=%s tz=%s(%s) screen=%sx%s@%s cpu=%s mem=%s geo=%s:%s",
        session.device_id[:12] + "...",
        session.oai_session_id[:12] + "...",
        session.auth_session_logging_id[:12] + "...",
        BrowserSession._short_value(fp.get("user_agent"), 72),
        fp.get("accept_language"),
        fp.get("timezone_iana"),
        fp.get("timezone_offset_minutes"),
        fp.get("screen_width"), fp.get("screen_height"), fp.get("device_pixel_ratio"),
        fp.get("hardware_concurrency"), fp.get("device_memory"),
        fp.get("geo_country") or "?", fp.get("geo_city") or "?",
    )

    create_acknowledged = False
    registration_password = None
    try:
        # The network pre-check must finish before signin/follow_authorize; the pre-check carries no email and does not trigger an OTP.
        network_preflight(session)
        human_delay("navigate")

        # Fill in the anonymous ChatGPT first-screen / model warm-up chain according to the 2026-07-19 HAR.
        if getattr(_protocol_cfg, "CHATGPT_ANON_BOOTSTRAP_ENABLED", True):
            from core.chatgpt_bootstrap import anonymous_bootstrap
            anonymous_bootstrap(
                session,
                strict=bool(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_STRICT", False)),
            )
            human_delay("navigate")

        # ==================== Stage 1: ChatGPT authentication ====================
        # Step 1: get providers
        providers = get_providers(session)
        human_delay("api")

        # Step 2: get CSRF token
        csrf_token = get_csrf_token(session)
        human_delay("api")

        # Step 3: initiate OAuth signin
        authorize_url = signin_openai(session, csrf_token, email)
        human_delay("api")

        # ==================== Stage 2: OpenAI Auth ====================
        # Step 4: follow the authorize URL (establishes the cookies of auth.openai.com)
        authorize_final_url = follow_authorize(session, authorize_url)
        human_delay("navigate")

        # Steps 5-8: force email + password registration, and do not use the passwordless OTP-only branch.
        navigate_create_account_password(session, authorize_final_url)
        human_delay("navigate")
        registration_password = generate_registration_password()
        password_sentinel = request_password_sentinel_bundle(session)
        password_sentinel_header, password_so_header = build_sentinel_header(
            session, password_sentinel, "username_password_create"
        )
        human_delay("challenge")
        register_result = register_user(
            session,
            email,
            registration_password,
            password_sentinel_header,
            password_so_header,
        )
        create_acknowledged = True

        # Only read verification codes that arrived after this send, to avoid taking historical emails by mistake.
        otp_after_ts = time.time()
        navigate_email_otp_send(session, register_result.get("continue_url"))
        human_delay("navigate")

        # ==================== Stage 3: verification code validation ====================
        # Sentinel Token Not generated in advance; generated right before the validate request once the OTP is in hand,
        # to avoid the challenge expiring while waiting for the email or being inconsistent with the state after a resend.

        # Waiting for the verification code: with USE_EMAIL_SERVICE=True it is fetched from Outlook automatically, otherwise entered manually.
        # If the verification code is wrong/expired, automatically resend and fetch the latest verification code again.
        validate_result = None
        max_otp_attempts = 3
        current_otp = otp_code
        for otp_attempt in range(1, max_otp_attempts + 1):
            if current_otp is None:
                if _email_cfg.USE_EMAIL_SERVICE:
                    logger.info(f"[OTP] Waiting for the verification code: {email} (attempt {otp_attempt}/{max_otp_attempts})")
                    current_otp = wait_for_otp(email, after_ts=otp_after_ts)
                else:
                    logger.info("")
                    logger.info(f"[OTP] Please check your email and enter the 6-digit verification code received (attempt {otp_attempt}/{max_otp_attempts}):")
                    current_otp = input(">>> verification code: ").strip()

            human_delay("otp_input")
            try:
                # HAR Aligned: email-otp/validate in the 2026-07-19 capture carries no Sentinel.
                # The switch is kept so the old logic can be restored when necessary.
                sentinel_header_9 = None
                so_header_9 = None
                if getattr(_protocol_cfg, "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", False):
                    sentinel_resp_9 = request_sentinel_token(session, "authorize_continue")
                    sentinel_header_9, so_header_9 = build_sentinel_header(session, sentinel_resp_9, "authorize_continue")
                    human_delay("challenge")

                # Step 10: submit the verification code
                validate_result = validate_email_otp(session, current_otp, sentinel_header_9, so_header_9)
                break
            except EmailOtpInvalidError as exc:
                if otp_attempt >= max_otp_attempts:
                    raise
                logger.warning(f"[OTP] Verification code wrong/expired: {str(exc)[:180]}, preparing to resend and fetch a new verification code")
                otp_after_ts = time.time()
                send_email_otp(session)
                human_delay("api")
                current_otp = None

        if validate_result is None:
            raise RuntimeError("OTP validation not completed")
        human_delay("api")

        # OTP The next step after validation is decided by the server-side auth session:
        #   - about_you: a new account that needs to continue submitting the name/birthday via create_account.
        #   - external_url: usually means the server can go straight to the OAuth callback (common for existing accounts / no profile page needed),
        #                   and forcing a create_account call then would trigger invalid_auth_step.
        page = validate_result.get("page") if isinstance(validate_result, dict) else {}
        page = page if isinstance(page, dict) else {}
        page_type = str(page.get("type") or "")
        otp_continue_url = (
            validate_result.get("continue_url")
            or validate_result.get("external_url")
            or validate_result.get("url")
            or page.get("continue_url")
            or page.get("external_url")
            or page.get("url")
        )
        logger.info(
            f"[Step 10] Next-branch decision: page_type={page_type or 'empty'}, "
            f"has_continue_url={bool(otp_continue_url)}"
        )

        # ==================== Stage 5/6: finish registration or go straight to the OAuth callback ====================
        otp_continue_text = str(otp_continue_url or "")
        direct_oauth_after_otp = bool(
            otp_continue_text
            and "about-you" not in otp_continue_text
            and (
                "chatgpt.com/api/auth/callback" in otp_continue_text
                or "auth.openai.com/authorize/continue" in otp_continue_text
                or page_type == "external_url"
            )
        )
        if page_type == "external_url" or direct_oauth_after_otp:
            if not otp_continue_url:
                raise RuntimeError(f"OTP external_url The response lacks a followable URL, cannot continue: {validate_result}")
            logger.info(f"[registration] After the OTP it entered the OAuth callback branch, skipping create_account:{email}")
            create_acknowledged = True
            session_info, access_token = _finalize_registration_session(
                session,
                otp_continue_url,
                email,
                callback_referer="https://auth.openai.com/email-verification",
            )
            if getattr(_protocol_cfg, "CHATGPT_AUTH_BOOTSTRAP_ENABLED", True):
                from core.chatgpt_bootstrap import authenticated_bootstrap
                authenticated_bootstrap(
                    session,
                    access_token,
                    strict=bool(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_STRICT", False)),
                )
            human_delay("post_auth")
        else:
            # Compatible with the case where the server only returns continue_url=/about-you but page.type is empty/changed.
            if page_type and page_type not in ("about_you", "about-you"):
                if otp_continue_url and "about-you" not in str(otp_continue_url):
                    raise RuntimeError(
                        f"OTP The following page type is unknown, do not blindly create_account: "
                        f"page_type={page_type}, resp={validate_result}"
                    )
                logger.warning(
                    f"[Step 10] Unknown page_type={page_type}, but continue_url points to about-you, continuing create_account"
                )

            # Navigate to about-you for real first, so the auth session/page state is consistent with create_account.
            about_url = str(otp_continue_url) if otp_continue_url and "about-you" in str(otp_continue_url) else None
            navigate_about_you(session, about_url)
            human_delay("navigate")

            # Step 11: get the Sentinel Token (oauth_create_account)
            sentinel_resp_11 = request_sentinel_token(session, "oauth_create_account")
            sentinel_header_11, so_header_11 = build_sentinel_header(session, sentinel_resp_11, "oauth_create_account")
            human_delay("challenge")

            human_delay("form")

            # Step 12: submit the user information to complete the registration
            create_result = create_account(session, name, birthday, sentinel_header_11, so_header_11)
            create_acknowledged = True

            logger.info(f"[registration] The create endpoint passed: {email}, continuing to complete the OAuth callback")
            human_delay("post_auth")

            # Step 12.5: follow the continue_url returned by create_account to complete the OAuth callback
            continue_url = create_result.get("continue_url")
            if not continue_url:
                raise RuntimeError(
                    f"create_account The response lacks continue_url, cannot continue: {create_result}"
                )

            # Step 13: pull /api/auth/session to extract the accessToken
            session_info, access_token = _finalize_registration_session(session, continue_url, email)
            if getattr(_protocol_cfg, "CHATGPT_AUTH_BOOTSTRAP_ENABLED", True):
                from core.chatgpt_bootstrap import authenticated_bootstrap
                authenticated_bootstrap(
                    session,
                    access_token,
                    strict=bool(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_STRICT", False)),
                )
            human_delay("post_auth")

        # ==================== Stage 7: set up 2FA (controlled by config.ENABLE_2FA)====================
        totp_secret = None
        if _twofa_cfg.ENABLE_2FA:
            # Steps 14-20: re-authentication (another email OTP must be received)→ enroll TOTP → activate
            try:
                totp_secret = setup_2fa(session, email)
            except Exception as exc:
                logger.error(f"2FA setup failed: {exc}")
                logger.debug("2FA error details:", exc_info=True)
                logger.warning("Will keep saving the account information (without the TOTP secret), which can be set manually later")
        else:
            logger.debug("2FA setup skipped (config.ENABLE_2FA=False)")

        # ==================== Stage 7.5: Codex OAuth (registration succeeded -> get the callback / CPA credential)====================
        # Log in to the email from scratch with a brand new clean session, following email OTP -> phone SMS verification (code receiving) -> pick workspace
        # →the standard path to get the code (the registration session is not reused, to avoid hitting choose-an-account).
        # Output:
        #   1) codex_result["callback_url"]  The whole Location that hit the redirect_uri (carrying code/state)
        #   2) codex_result["file_path"]     CPA directly importable codex-{email}.json
        codex_result = {"status": "skipped", "ok": False, "message": "not triggered"}
        try:
            from core.codex_oauth import run_codex_oauth
            codex_result = run_codex_oauth(email)
        except Exception as exc:
            codex_result = {
                "status": "failed",
                "ok": False,
                "message": f"{type(exc).__name__}: {str(exc)[:180]}",
            }

        if codex_result.get("ok"):
            logger.info(
                f"[Codex] Success: {email},file={codex_result.get('file_path')},"
                f"callback={codex_result.get('callback_url')}"
            )
        elif codex_result.get("status") == "skipped":
            logger.info(f"[Codex] Skipped: {email}, reason={codex_result.get('message')}")
        else:
            logger.warning(
                f"[Codex] Failed: {email}, reason={codex_result.get('message')}"
            )

        # ==================== Stage 8: persist the account ====================
        from core.email_provider import resolve_email_source
        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(email),
            proxy_used=session.proxy or None,
            batch_dir=batch_dir,
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "device_id": session.device_id,
                "sentinel_sid": getattr(session, "sentinel_sid", None),
                "browser_profile": getattr(session, "browser_profile", None),
                "registration_password": registration_password,
                "codex": codex_result,
            },
        )

        logger.info(f"[done] {email}, account ID={account_id},Token={access_token[:16]}...")

        # ==================== Stage 9: post-trigger flow ====================
        # Only accounts that completed the callback, got a token and were saved successfully trigger the flow.
        # flow request does not affect the account save state, but its result is recorded and counted in the batch statistics.
        flow_result = {"status": "skipped", "ok": False, "message": "not triggered"}
        try:
            from core.flow_trigger import trigger_flow
            flow_result = trigger_flow(access_token)
        except Exception as exc:
            flow_result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {exc}"}

        if flow_result.get("ok"):
            logger.info(
                f"[Flow] Success: {email},HTTP={flow_result.get('http_status')}, "
                f"flow_id={flow_result.get('flow_id') or 'unresolved'}"
            )
        elif flow_result.get("status") == "skipped":
            logger.info(f"[Flow] Skipped: {email}, reason={flow_result.get('message')}")
        else:
            logger.warning(
                f"[Flow] Failed: {email},HTTP={flow_result.get('http_status') or 'none'}, "
                f"reason={flow_result.get('message')}"
            )

        logger.debug(f"[done] TOTP Secret: {totp_secret or '(Not set)'}")

        # Success criterion of a registration task: the account itself (registration + token) and the Codex authorization must both succeed to count as success.
        # Codex On failure the account is still saved (the token was obtained and there is a chance to rerun), but the task state is marked failed,
        # so the WebUI task table can clearly tell "fully successful" from "missing Codex".
        codex_ok = codex_result.get("ok") or codex_result.get("status") == "skipped"
        task_success = codex_ok
        task_error = None
        if not task_success:
            task_error = f"Codex not completed: {codex_result.get('message', 'unknown')}"
            logger.warning(f"[task result] {email} account saved but the task marked failed, reason: {task_error}")

        return {"success": task_success, "email": email, "account_id": account_id,
                "access_token": access_token, "totp_secret": totp_secret,
                "flow": flow_result, "codex": codex_result,
                "error": task_error}

    except Exception as e:
        logger.error(f"[failed] {email}: {type(e).__name__}: {e}")
        logger.debug("Detailed error information:", exc_info=True)
        # Email state reclaim policy, three cases:
        #   1. Account dead (account_deactivated etc.): the email material itself is unusable, mark it failed and drop it directly.
        #   2. Failure after the create endpoint passed: the remote side has consumed this email, abandon it directly to avoid registering again.
        #   3. Ordinary failure before the create endpoint passed: the email can still be tried next time, put it back to available.
        from core.openai_auth import AccountUnusableError
        account_dead = isinstance(e, AccountUnusableError)
        try:
            if email:
                from core.email_provider import release_email
                if account_dead:
                    src = release_email(
                        email, status="failed",
                        note=f"Account is dead, the email is unusable: {str(e)[:180]}",
                    )
                    logger.warning(f"[email:{src}] {email} account is dead, marked failed, will not be registered again")
                elif create_acknowledged:
                    src = release_email(
                        email, status="failed",
                        note=f"The create endpoint passed but a later step failed, abandoned: {str(e)[:180]}",
                    )
                    logger.warning(f"[email:{src}] {email} was created but a later step failed, marked failed, will not be registered again")
                else:
                    src = release_email(email, status="available", note=f"last failure: {str(e)[:180]}")
                    logger.info(f"[email:{src}] {email} restored available")
        except Exception:
            pass
        return {"success": False, "email": email, "error": str(e)}


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="ChatGPT protocol registration CLI")
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of consecutive registrations, default 1")
    parser.add_argument("--workers", type=int, default=1, help="Number of concurrent registration threads, default 1 (serial)")
    parser.add_argument("--delay", type=float, default=0, help="Interval in seconds after each registration ends")
    parser.add_argument("--continue-on-fail", action="store_true", help="Continue with the next registration after a single account fails")
    parser.add_argument("--verbose", action="store_true", help="Show detailed step logs and error stack traces")
    args = parser.parse_args()
    configure_logging(args.verbose)

    if args.count < 1:
        logger.error("The registration count must be greater than 0")
        sys.exit(1)

    if args.workers < 1:
        logger.error("The number of concurrent threads must be greater than 0")
        sys.exit(1)

    if args.count > 1 and REGISTER_EMAIL:
        logger.error("config.REGISTER_EMAIL An email is fixed, which is not suitable for batch registration; please clear it before using --count")
        sys.exit(1)

    if args.workers > 1 and not _email_cfg.USE_EMAIL_SERVICE:
        logger.error("Multi-threaded registration requires enabling Outlook automatic retrieval; please enable USE_EMAIL_SERVICE or switch to --workers 1")
        sys.exit(1)

    if args.workers > args.count:
        logger.info(f"[batch] The number of concurrent threads {args.workers} is larger than the target count, running {args.count} tasks")
        args.workers = args.count

    if args.workers > 1:
        batch_dir = create_batch_archive_dir(args.count, args.workers)
        logger.info("[batch] Account data will be written directly to SQLite")
        results = run_parallel_batch(args.count, args.workers, args.delay, args.continue_on_fail, batch_dir)
    else:
        batch_dir = create_batch_archive_dir(args.count, args.workers)
        logger.info("[batch] Account data will be written directly to SQLite")
        results = run_serial_batch(args.count, args.delay, args.continue_on_fail, batch_dir)

    success_count = sum(1 for r in results if _is_success(r))
    flow_success_count = sum(
        1 for r in results
        if _is_success(r) and isinstance(r.get("flow"), dict) and r["flow"].get("ok")
    )
    flow_failed_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("flow"), dict)
        and r["flow"].get("status") == "failed"
    )
    flow_skipped_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("flow"), dict)
        and r["flow"].get("status") == "skipped"
    )
    codex_success_count = sum(
        1 for r in results
        if _is_success(r) and isinstance(r.get("codex"), dict) and r["codex"].get("ok")
    )
    codex_failed_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("codex"), dict)
        and r["codex"].get("status") == "failed"
    )
    codex_skipped_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("codex"), dict)
        and r["codex"].get("status") == "skipped"
    )
    logger.info(f"[batch] Done: success {success_count} / attempted {len(results)} / target {args.count}")
    if success_count:
        logger.info(
            f"[batch] Flow: success {flow_success_count} / failed {flow_failed_count} / skipped {flow_skipped_count}"
        )
        logger.info(
            f"[batch] Codex: success {codex_success_count} / failed {codex_failed_count} / skipped {codex_skipped_count}"
        )
    sys.exit(0 if success_count == args.count else 1)


def run_one_batch_item(index: int, total: int, batch_dir=None) -> dict:
    """Run one task of the batch registration and return a structured result."""
    logger.info(f"[batch] Starting registration {index + 1}/{total}")
    try:
        email, name, birthday = prepare_registration_inputs()
        return run_registration(
            email=email,
            name=name,
            birthday=birthday,
            batch_dir=batch_dir,
            # proxy Not passed -> the BrowserSession draws one from PROXY_POOL at random
        )
    except Exception as exc:
        logger.error(f"[batch] Preparation phase of registration {index + 1} failed: {type(exc).__name__}: {exc}")
        logger.debug("Preparation phase error details:", exc_info=True)
        return {"success": False, "error": str(exc)}


def run_serial_batch(count: int, delay: float, continue_on_fail: bool, batch_dir=None) -> list[dict]:
    """Run the batch registration serially in the original way."""
    results = []
    for index in range(count):
        result = run_one_batch_item(index, count, batch_dir)
        results.append(result)
        if not _is_success(result) and not continue_on_fail:
            logger.error("[batch] The current account failed, stopped. To keep going you can add --continue-on-fail")
            break

        if delay > 0 and index < count - 1:
            logger.info(f"[batch] Waiting {delay} seconds before continuing")
            time.sleep(delay)
    return results


def run_parallel_batch(
    count: int,
    workers: int,
    delay: float,
    continue_on_fail: bool,
    batch_dir=None,
) -> list[dict]:
    """Run the batch registration concurrently with a thread pool."""
    logger.info(f"[batch] Multi-threaded registration enabled: target {count}, concurrency {workers}")
    if delay > 0:
        logger.info(f"[batch] In concurrent mode --delay={delay} means the staggered interval between task submissions")

    results: list[dict] = []
    future_to_index = {}
    next_index = 0
    stop_submitting = False

    def submit_next(executor: ThreadPoolExecutor) -> bool:
        nonlocal next_index
        if stop_submitting or next_index >= count:
            return False
        future = executor.submit(run_one_batch_item, next_index, count, batch_dir)
        future_to_index[future] = next_index
        next_index += 1
        if delay > 0 and next_index < count:
            time.sleep(delay)
        return True

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="reg-cli") as executor:
        while len(future_to_index) < workers and submit_next(executor):
            pass

        while future_to_index:
            done, _ = wait(future_to_index, return_when=FIRST_COMPLETED)
            for future in done:
                index = future_to_index.pop(future)
                try:
                    result = future.result()
                except Exception as exc:
                    logger.error(f"[batch] Registration thread {index + 1}/{count} raised an exception: {type(exc).__name__}: {exc}")
                    logger.debug("Thread error details:", exc_info=True)
                    result = {"success": False, "error": str(exc)}
                results.append(result)

                if not _is_success(result) and not continue_on_fail:
                    stop_submitting = True
                    logger.error("[batch] The current account failed, submitting new tasks stopped. Tasks already started will run to completion.")

            while len(future_to_index) < workers and submit_next(executor):
                pass

    return results


if __name__ == "__main__":
    main()
