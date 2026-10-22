# -*- coding: utf-8 -*-
"""Run the Codex OAuth authorization through the RoxyBrowser fingerprint browser."""
from __future__ import annotations

import logging
import random
import time
from contextvars import ContextVar
from urllib.parse import urlparse

from config import roxybrowser as _roxy_cfg
from core.email_provider import wait_for_otp
from core.humanize import delay as human_delay
from core import sms_provider
from core.openai_auth import AccountUnusableError, detect_account_unusable_response_body
from core.roxybrowser_client import RoxyBrowserClient
from core import codex_oauth as _codex_proto
from core.roxy_registration import (
    _build_driver,
    _center_browser_window,
    _click_any,
    _click_continue,
    _find_any,
    _maybe_accept,
    _human_click,
    _human_type_text,
    _type_any,
    _type_email_address,
    _submit_email_step,
    _click_email_entry_option,
    _type_otp,
    _clear_otp_inputs,
    _email_otp_page_state,
    _is_email_verification_page,
    _is_login_password_page,
    _click_passwordless_signup_if_present,
)

_base_logger = logging.getLogger(__name__)
_CODEX_BROWSER_KIND: ContextVar[str] = ContextVar("codex_browser_kind", default="Roxy")


def _codex_prefix() -> str:
    return f"[Codex][{_CODEX_BROWSER_KIND.get()}]"


def _codex_driver_name() -> str:
    return _CODEX_BROWSER_KIND.get()


def _detect_browser_kind(opened=None) -> str:
    try:
        raw = getattr(opened, "raw", None) or {}
        if isinstance(raw, dict) and str(raw.get("driver") or "").lower().startswith("cloak"):
            return "Cloak"
    except Exception:
        pass
    return "Roxy"


class _CodexLogger:
    """Replace the internal placeholder prefix of the flow with the actual current browser type."""
    def __init__(self, base):
        self._base = base

    def _msg(self, msg):
        return str(msg).replace("[Codex][Browser]", _codex_prefix())

    def debug(self, msg, *args, **kwargs):
        return self._base.debug(self._msg(msg), *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        return self._base.info(self._msg(msg), *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        return self._base.warning(self._msg(msg), *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        return self._base.error(self._msg(msg), *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        return self._base.exception(self._msg(msg), *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._base, name)


logger = _CodexLogger(_base_logger)


def _is_callback_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return (
        parsed.scheme in ("http", "https")
        and parsed.hostname in ("localhost", "127.0.0.1")
        and parsed.port == 1455
        and parsed.path == "/auth/callback"
    )


def _extract_callback_url_from_page(driver) -> str:
    """Extract the OAuth callback URL from the current page.

    When the browser navigates to http://localhost:1455/auth/callback?... and no local service is listening, it shows
    chrome-error://chromewebdata/. The address bar may turn into chrome-error, but the Chromium
    performance navigation entry still keeps the original callback URL, which can be extracted directly and submitted to CPA.
    """
    try:
        current = str(driver.current_url or "")
        if _is_callback_url(current):
            return current
    except Exception:
        pass
    try:
        urls = driver.execute_script(r"""
        const out = [];
        const push = v => { if (v && typeof v === 'string') out.push(v); };
        try { push(location.href); } catch (e) {}
        try { push(document.URL); } catch (e) {}
        try { push(document.documentURI); } catch (e) {}
        try { for (const e of performance.getEntriesByType('navigation')) push(e.name); } catch (e) {}
        try { for (const e of performance.getEntries()) push(e.name); } catch (e) {}
        return [...new Set(out)];
        """) or []
        for url in urls:
            if _is_callback_url(str(url)):
                logger.info("[Codex][Browser] Extracted the callback URL from the browser performance records:%s", str(url)[:160])
                return str(url)
    except Exception as exc:
        logger.debug("[Codex][Browser] Failed to extract the callback URL from the page:%s", exc)
    return ""


def _extract_callback_url_from_any_window(driver) -> str:
    found = _extract_callback_url_from_page(driver)
    if found:
        return found
    try:
        for handle in list(getattr(driver, "window_handles", []) or []):
            try:
                driver.switch_to.window(handle)
                found = _extract_callback_url_from_page(driver)
                if found:
                    return found
            except Exception:
                continue
    except Exception:
        pass
    return ""


def _wait_for_callback(driver, timeout: int | None = None) -> str:
    end = time.time() + (timeout or int(_roxy_cfg.ROXY_CODEX_CALLBACK_TIMEOUT))
    last_url = ""
    while time.time() < end:
        try:
            current = str(driver.current_url or "")
            if current != last_url:
                logger.debug("[Codex][Browser] current URL: %s", current)
                last_url = current
            callback = _extract_callback_url_from_any_window(driver)
            if callback:
                return callback
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for the Codex callback, last URL={last_url}")


def _click_if_present(driver, selectors: list[str], timeout: int = 3) -> bool:
    try:
        _click_any(driver, selectors, timeout=timeout)
        return True
    except Exception:
        return False


def _maybe_click_passwordless_after_email(driver, email: str, timeout: int = 18) -> None:
    """
    Codex OAuth After submitting the email it may also jump to /log-in/password or /create-account/password.
    Prefer clicking the "use a one-time code" entry to reach the email verification code page.
    """
    end = time.time() + timeout
    last_url = ""
    clicked = False
    while time.time() < end:
        try:
            if _is_email_verification_page(driver):
                if clicked:
                    logger.info("[Codex][Browser] Entered the email verification code page through the one-time code entry")
                return
            url = str(driver.current_url or "")
            if url != last_url:
                logger.info("[Codex][Browser] Detected the password/OTP jump after submitting the email:url=%s", url or "-")
                last_url = url
            lower = url.lower()
            if any(x in lower for x in ("phone", "workspace", "consent", "authorize", "localhost:1455")):
                return
            if "/password" in lower or "auth.openai.com" in lower:
                result = _click_passwordless_signup_if_present(driver)
                if result.get("ok"):
                    clicked = True
                    logger.info("[Codex][Browser] Clicked the one-time code entry:email=%s detail=%s", email, result)
                    human_delay("form")
                    continue
        except Exception as exc:
            logger.debug("[Codex][Browser] Probing the one-time code entry on the password page failed:%s", str(exc)[:140])
        time.sleep(0.5)
    if clicked:
        logger.info("[Codex][Browser] Clicked the one-time code entry, the OTP page was not detected immediately, continuing with the OTP polling")


def _wait_for_otp_input(driver, timeout: int = 30) -> None:
    """The verification code was received but the OTP input box may not have appeared yet (after clicking the one-time code there is often an intermediate page / delayed rendering).

    While waiting, if still on the login password page, click the one-time code entry again (at most 2 times, 6s apart);
    if it still has not appeared after the timeout, print the page state to help locate the problem.
    """
    end = time.time() + timeout
    passwordless_retries = 0
    while time.time() < end:
        if _is_email_verification_page(driver):
            return
        if _is_login_password_page(driver) and passwordless_retries < 2:
            passwordless_retries += 1
            result = _click_passwordless_signup_if_present(driver)
            if result.get("ok"):
                logger.info("[Codex][Browser] Still on the login password page, clicking the one-time code entry again:%s", result.get("reason"))
                human_delay("form")
            time.sleep(6)
            continue
        time.sleep(0.8)
    state = _email_otp_page_state(driver)
    logger.warning(
        "[Codex][Browser] Timed out waiting for the OTP input box, page url=%s inputs=%s buttons=%s first 300 characters of text=%s",
        str(state.get("url") or ""),
        len(state.get("inputs") or []),
        [(b.get("text") or "")[:24] for b in (state.get("buttons") or [])][:8],
        str(state.get("text") or "")[:300],
    )
    raise RuntimeError("Timed out waiting for the OTP input box, the verification code input box did not appear on the page")


def _account_password_for_email(email: str) -> str:
    try:
        return _codex_proto._account_registration_password(email)
    except Exception:
        return ""


def _account_totp_code_for_email(email: str) -> str:
    try:
        return _codex_proto._account_totp_code(email)
    except Exception:
        return ""


def _is_mfa_challenge_page(driver) -> bool:
    try:
        url = str(driver.current_url or "").lower()
        if "/mfa-challenge/" in url or "/mfa-challenge" in url:
            return True
        state = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const form = [...document.querySelectorAll('form')].find(f => /\/mfa-challenge/i.test(f.getAttribute('action') || ''));
        const input = form ? [...form.querySelectorAll('input[name="code"], input[autocomplete="one-time-code"], input[maxlength="6"]')].find(visible) : null;
        return {ok: !!(form && input), url: location.href};
        """) or {}
        return bool(state.get("ok"))
    except Exception:
        return False


def _fill_mfa_challenge_if_present(driver, email: str, timeout: int = 15) -> bool:
    """If the page is currently an MFA challenge page, automatically fill in the account TOTP and submit."""
    code = _account_totp_code_for_email(email)
    if not code:
        return False
    end = time.time() + timeout
    while time.time() < end:
        try:
            if not _is_mfa_challenge_page(driver):
                time.sleep(0.4)
                continue
            result = driver.execute_script(r"""
            const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
              && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
              && !el.disabled && !el.readOnly;
            const form = [...document.querySelectorAll('form')].find(f => /\/mfa-challenge/i.test(f.getAttribute('action') || ''));
            if (!form) return {ok:false, reason:'missing_form'};
            const input = [...form.querySelectorAll('input[name="code"], input[autocomplete="one-time-code"], input[maxlength="6"]')].find(visible);
            if (!input) return {ok:false, reason:'missing_code_input'};
            const button = [...form.querySelectorAll('button[type="submit"], button[data-dd-action-name="Continue"], button')].find(visible);
            if (!button) return {ok:false, reason:'missing_submit'};
            return {ok:true, input, button};
            """) or {}
            if not result.get("ok"):
                time.sleep(0.4)
                continue
            _human_type_text(driver, result.get("input"), code, clear=True)
            human_delay("otp_input")
            _human_click(driver, result.get("button"), label="codex_mfa_submit")
            logger.info("[Codex][Browser] Filled in and submitted the MFA verification code:%s", email)
            wait_end = time.time() + 12
            while time.time() < wait_end:
                if not _is_mfa_challenge_page(driver):
                    return True
                time.sleep(0.4)
            return True
        except Exception as exc:
            logger.debug("[Codex][Browser] MFA challenge handling failed:%s", str(exc)[:160])
            time.sleep(0.5)
    return False


def _fill_login_password_if_present(driver, email: str, timeout: int = 18) -> str | None:
    """Codex OAuth If the account has a password, enter it on the login password page first. Returns next_step / email_otp / None."""
    password = _account_password_for_email(email)
    if not password:
        return None
    end = time.time() + timeout
    while time.time() < end:
        if _is_email_verification_page(driver):
            return "email_otp"
        if not _is_login_password_page(driver):
            time.sleep(0.4)
            continue
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="current-password"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_password_input'};
        const form = input.closest('form');
        const scope = form || document;
        const buttons = [...scope.querySelectorAll('button,input[type="submit"]')]
          .filter(el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true')
          .map((el, idx) => {
            const r = el.getBoundingClientRect();
            const ir = input.getBoundingClientRect();
            return {el, idx, below: r.top >= ir.bottom - 10, dist: Math.max(0, r.top - ir.bottom) + Math.abs((r.left+r.right-ir.left-ir.right)/2)/10};
          })
          .filter(x => x.below)
          .sort((a,b) => a.dist - b.dist || a.idx - b.idx);
        if (!buttons.length) return {ok:false, reason:'missing_submit'};
        buttons[0].el.scrollIntoView({block:'center'});
        return {ok:true, reason:'password_targets', input, button: buttons[0].el};
        """) or {}
        if not result.get("ok"):
            logger.info("[Codex][Browser] Input/submit button not found on the login password page:%s", result)
            time.sleep(0.5)
            continue
        _human_type_text(driver, result.get("input"), password, clear=True)
        human_delay("form", minimum=2.0, maximum=3.6)
        _human_click(driver, result.get("button"), label="codex_password_submit")
        logger.info("[Codex][Browser] Filled in and submitted the login password:%s", email)
        wait_end = time.time() + 12
        while time.time() < wait_end:
            if _is_mfa_challenge_page(driver):
                _fill_mfa_challenge_if_present(driver, email, timeout=15)
                return "next_step"
            if _is_email_verification_page(driver):
                return "email_otp"
            if not _is_login_password_page(driver):
                return "next_step"
            time.sleep(0.5)
        return "next_step"
    return None


def _fill_email_and_otp(driver, email: str, otp_provider, auth_url: str) -> None:
    otp_after_ts = time.time()
    logger.info("[Codex][Browser] Opening the authorization URL")
    logger.info("[Codex][Browser] Full authorization URL: %s", auth_url)
    driver.get(auth_url)
    human_delay("navigate")
    logger.info("[Codex][Browser] Authorization page loaded, checking whether an email login is needed")
    _maybe_accept(driver)

    # It may already be on the account selection / authorization page; if there is an email input box, do the full login.
    # With a non-Japan exit the button wording/order changes, so "Continue" must not be clicked by visible text, otherwise Google may be clicked by mistake.
    try:
        _type_email_address(driver, email, timeout=12)
        logger.info("[Codex][Browser] Email filled in:%s", email)
        human_delay("form")
        _submit_email_step(driver)
        logger.info("[Codex][Browser] Email submitted, waiting for the email OTP page")
        pw_result = _fill_login_password_if_present(driver, email, timeout=18)
        if pw_result == "next_step":
            if _is_mfa_challenge_page(driver):
                _fill_mfa_challenge_if_present(driver, email, timeout=15)
            logger.info("[Codex][Browser] The account has logged in with its password, going straight to the following steps")
            return
        if pw_result == "email_otp":
            logger.info("[Codex][Browser] After the password login it still entered the email OTP page")
        else:
            _maybe_click_passwordless_after_email(driver, email, timeout=18)
    except Exception as exc:
        logger.info("[Codex][Browser] No email input box detected, possibly already logged in or moved on to the next step:%s", str(exc)[:120])
        return

    # After submitting the email no global "continue/authorize/branch" fallback click is performed any more; afterwards we only wait for the verification code page.
    # This avoids wrongly clicking the authorize button when the page has already entered OAuth consent.

    used_codes: set[str] = set()
    max_otp_attempts = 3

    def _restart_email_otp_flow(reason: str) -> None:
        """Codex Auth Clicking resend directly on the page may trigger a server 500; here we instead re-open the authorization URL and submit the email."""
        nonlocal otp_after_ts
        logger.info("[Codex][Browser] Re-triggering the email OTP:%s", reason)
        otp_after_ts = time.time()
        driver.get(auth_url)
        human_delay("navigate")
        _maybe_accept(driver)
        try:
            _type_email_address(driver, email, timeout=12)
            human_delay("form")
            _submit_email_step(driver)
            logger.info("[Codex][Browser] Resubmitted the email to trigger the OTP")
            pw_result = _fill_login_password_if_present(driver, email, timeout=12)
            if pw_result == "next_step":
                if _is_mfa_challenge_page(driver):
                    _fill_mfa_challenge_if_present(driver, email, timeout=15)
                logger.info("[Codex][Browser] After resubmitting the email the account logged in with its password, going to the following steps")
                return
            if pw_result != "email_otp":
                _maybe_click_passwordless_after_email(driver, email, timeout=12)
        except Exception as exc:
            # If after re-entering the authorization URL we are already on the verification code / next-step page, do not force a submit again.
            if not _is_email_verification_page(driver):
                logger.warning("[Codex][Browser] Resubmitting the email failed, continuing to poll on the current page:%s", str(exc)[:180])
            else:
                logger.info("[Codex][Browser] After re-opening the authorization we are already on the email OTP page")
        human_delay("api")

    for otp_attempt in range(1, max_otp_attempts + 1):
        logger.info("[Codex][Browser] Waiting for the email OTP: %s (attempt %s/%s)", email, otp_attempt, max_otp_attempts)
        try:
            code = _wait_for_fresh_email_otp(
                otp_provider,
                email,
                after_ts=otp_after_ts,
                used_codes=used_codes,
                timeout=90,
            )
        except Exception as exc:
            if otp_attempt >= max_otp_attempts:
                raise
            logger.warning(
                "[Codex][Browser] No email OTP received for a long time, clicking 'resend email' and continuing to wait (next round %s/%s):%s: %s",
                otp_attempt + 1,
                max_otp_attempts,
                type(exc).__name__,
                str(exc)[:180],
            )
            _restart_email_otp_flow("Timed out waiting for the verification code, avoiding clicking resend which causes 500")
            continue
        used_codes.add(str(code))
        logger.info("[Codex][Browser] Email OTP received:%s", code)
        _wait_for_otp_input(driver, timeout=30)
        _clear_otp_inputs(driver)
        _type_otp(driver, code)
        logger.info("[Codex][Browser] Filled in the email OTP")
        human_delay("otp_input")
        _install_email_otp_validate_hook(driver)
        clicked = _click_if_present(driver, [
            "button[type='submit']",
            "//button[contains(., 'Continue')]",
            "//button[contains(., '继续')]",
            "//button[contains(., 'Verify')]",
            "//button[contains(., '验证')]",
        ], timeout=8)
        if clicked:
            logger.info("[Codex][Browser] Email OTP submitted, waiting for the following authorization / phone number page")
        else:
            logger.info("[Codex][Browser] No explicit submit button found, continuing to wait for the page state")

        outcome = _wait_after_email_otp_submit(driver, timeout=45)
        logger.info("[Codex][Browser] State after submitting the email OTP:%s", outcome)
        if _is_mfa_challenge_page(driver):
            _fill_mfa_challenge_if_present(driver, email, timeout=15)
            return
        if outcome == "accepted":
            return
        if str(outcome).startswith("deactivated:"):
            error_code = str(outcome).split(":", 1)[1] or "account_deactivated"
            raise AccountUnusableError(f"Account is dead ({error_code})", error_code=error_code)

        if otp_attempt >= max_otp_attempts:
            raise RuntimeError("Codex Email verification code wrong/expired repeatedly, the maximum number of retries has been reached")

        logger.warning(
            "[Codex][Browser] Email verification code wrong/expired or the page did not move on, preparing to resend and fetch the latest verification code (%s/%s)",
            otp_attempt + 1,
            max_otp_attempts,
        )
        _restart_email_otp_flow("Verification code wrong/expired or the page did not move on, avoiding clicking resend which causes 500")



def _wait_for_fresh_email_otp(otp_provider, email: str, after_ts: float, used_codes: set[str] | None = None, timeout: int = 90) -> str:
    """Get an email OTP that has not been submitted yet.

    The code retrieval API of generic API emails sometimes returns a cached old code first; when resending after a wrong code,
    the already failed code is refused here, and polling continues until a new code appears or the timeout is reached.
    """
    used_codes = {str(x) for x in (used_codes or set()) if x}
    end = time.time() + timeout
    last_code = ""
    while True:
        code = str(otp_provider(email, after_ts=after_ts) or "").strip()
        if code and code not in used_codes:
            return code
        last_code = code or last_code
        remaining = int(end - time.time())
        if remaining <= 0:
            raise RuntimeError(f"Timed out waiting for a new email verification code, the code retrieval API still returns the failed verification code:{last_code or '-'}")
        logger.warning(
            "[Codex][Browser] The code retrieval API still returns the already submitted old OTP=%s, continuing to wait for the latest verification code (%ss remaining)",
            last_code or "-",
            remaining,
        )
        time.sleep(min(5, max(1, remaining)))


def _install_email_otp_validate_hook(driver) -> None:
    """
    Hook fetch/XHR inside the page and capture the response body of the email-otp/validate API.

    A fingerprint browser cannot get requests.Response directly like the pure protocol mode, so before submitting the email OTP
    this hook is injected, and afterwards only the JSON error.code of the API is read, without judging dead accounts by page text.
    """
    script = r"""
    (() => {
      window.__codexEmailOtpValidateResponses = [];
      if (window.__codexEmailOtpValidateHooked) return true;
      window.__codexEmailOtpValidateHooked = true;
      const hit = (url) => String(url || '').includes('/api/accounts/email-otp/validate');
      const save = (url, status, body) => {
        try {
          if (!hit(url)) return;
          window.__codexEmailOtpValidateResponses.push({
            url: String(url || ''),
            status: Number(status || 0),
            body: String(body || '').slice(0, 2000),
            ts: Date.now(),
          });
        } catch (e) {}
      };
      const origFetch = window.fetch;
      if (origFetch) {
        window.fetch = async function(input, init) {
          const resp = await origFetch.apply(this, arguments);
          try {
            const url = (typeof input === 'string') ? input : (input && input.url);
            if (hit(url)) {
              resp.clone().text().then(t => save(url, resp.status, t)).catch(() => {});
            }
          } catch (e) {}
          return resp;
        };
      }
      const origOpen = XMLHttpRequest.prototype.open;
      const origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url) {
        this.__codexOtpValidateUrl = url;
        return origOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function() {
        try {
          this.addEventListener('loadend', function() {
            try {
              if (hit(this.__codexOtpValidateUrl)) save(this.__codexOtpValidateUrl, this.status, this.responseText);
            } catch (e) {}
          });
        } catch (e) {}
        return origSend.apply(this, arguments);
      };
      return true;
    })();
    """
    try:
        driver.execute_script(script)
    except Exception as exc:
        logger.debug("[Codex][Browser] Failed to inject the email-otp/validate response hook:%s", exc)


def _read_email_otp_validate_dead_code(driver) -> str:
    try:
        rows = driver.execute_script("return window.__codexEmailOtpValidateResponses || [];") or []
    except Exception:
        return ""
    if not isinstance(rows, list):
        return ""
    for row in reversed(rows):
        if not isinstance(row, dict):
            continue
        code = detect_account_unusable_response_body(str(row.get("body") or ""))
        if code:
            logger.warning(
                "[Codex][Browser] email-otp/validate Account recognized as dead from the response:code=%s status=%s",
                code,
                row.get("status"),
            )
            return code
    return ""


# The email verification code page check reuses the strong version of roxy_registration (URL + input attribute recognition,
# and explicitly excluding /log-in/password), not the local weakened version, to avoid that after clicking the one-time code
# the page has rendered the OTP input box but is not recognized because the URL lacks email-verification.

def _wait_after_email_otp_submit(driver, timeout: int = 45) -> str:
    """
    After submitting the email OTP, wait for the page to leave /email-verification.

    Returns:
      - accepted: left the email verification code page / entered the phone number page / entered the callback;
      - invalid: the page clearly reports an error, the input box turns red, or the verification code page is kept for a long time.
    """
    end = time.time() + timeout
    last_url = ""
    last_log = 0.0
    while time.time() < end:
        try:
            dead_code = _read_email_otp_validate_dead_code(driver)
            if dead_code:
                return f"deactivated:{dead_code}"
            url = str(driver.current_url or "")
            if url != last_url:
                logger.info("[Codex][Browser] Waiting for the redirect after the email OTP:url=%s", url)
                last_url = url
            if _is_callback_url(url):
                return "accepted"
            if _has_strict_add_phone_form(driver) or _is_phone_code_page(driver):
                return "accepted"
            # Already left email-verification, handing over to the following authorization / phone number / consent flow.
            if "email-verification" not in url.lower():
                return "accepted"

            state = _email_otp_page_state(driver)
            invalid = any(str(i.get("ariaInvalid") or "").lower() == "true" for i in (state.get("inputs") or []))
            errors = [str(x) for x in (state.get("errors") or []) if str(x).strip()]
            body_text = str(state.get("text") or "").lower()
            error_hit = any(x in body_text for x in (
                "invalid code", "incorrect code", "wrong code", "expired",
                "验证码错误", "验证码无效", "验证码已过期", "コードが正しく", "無効", "期限",
            ))
            if invalid or errors or error_hit:
                logger.warning(
                    "[Codex][Browser] Error / verification code still required detected after the email OTP submit:errors=%s invalid=%s url=%s",
                    errors[:3],
                    invalid,
                    url,
                )
                return "invalid"

            if time.time() - last_log > 6:
                logger.info("[Codex][Browser] Still on email-verification after the email OTP, continuing to wait for the page to redirect automatically")
                last_log = time.time()
        except Exception:
            pass
        time.sleep(0.5)
    logger.warning("[Codex][Browser] Timed out waiting for the redirect after the email OTP, current url=%s, handled as invalid/expired verification code", getattr(driver, "current_url", ""))
    return "invalid"


def _phone_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const radios = [...document.querySelectorAll('input[type=radio]')].filter(visible).map(el => ({
          name: el.name || '', value: el.value || '', checked: !!el.checked, id: el.id || ''
        }));
        const inputs = [...document.querySelectorAll('input,select,textarea')].filter(visible).map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
          id: el.id || '', autocomplete: el.getAttribute('autocomplete') || '', placeholder: el.getAttribute('placeholder') || '',
          ariaInvalid: el.getAttribute('aria-invalid') || '', value: el.value || ''
        }));
        const forms = [...document.querySelectorAll('form')].map(f => ({action: f.getAttribute('action') || ''}));
        const bodyText = (document.body?.innerText || '').slice(0, 1200);
        return {url: location.href, radios, inputs, forms, bodyText};
        """) or {}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "url": getattr(driver, 'current_url', '')}


def _select_sms_channel_or_raise(driver) -> None:
    state = _phone_page_state(driver)
    radios = state.get('radios') or []
    # If WhatsApp exists and there is no SMS/text option, the current code-receiving platform cannot read WhatsApp, so switch numbers directly.
    has_whatsapp = any('whatsapp' in str(r.get('value','')).lower().replace(' ', '') for r in radios)
    has_sms = any(str(r.get('value','')).lower() in ('sms', 'text', 'text_message', 'text-message') for r in radios)
    if has_whatsapp and not has_sms:
        raise RuntimeError(f"whatsapp_channel: The page only offers the WhatsApp channel state={state}")
    # Select the SMS/text radio. Without a radio it may default to SMS.
    selected = driver.execute_script(r"""
    const radios = [...document.querySelectorAll('input[type=radio]')];
    const sms = radios.find(el => /^(sms|text|text_message|text-message)$/i.test(el.value || ''));
    if (!sms) return false;
    sms.click();
    sms.dispatchEvent(new Event('input', {bubbles:true}));
    sms.dispatchEvent(new Event('change', {bubbles:true}));
    return true;
    """)
    if selected:
        logger.info("[Codex][Browser] Selected the SMS text message channel")


def _is_phone_code_state(state: dict) -> bool:
    url = str(state.get('url') or '').lower()
    if 'email-verification' in url:
        # The email OTP page also has autocomplete=one-time-code, so it must not be mistaken for the phone verification code page.
        return False
    if 'phone-verification' in url:
        return True
    forms = state.get('forms') or []
    form_actions = ' '.join(str(f.get('action') or '') for f in forms).lower()
    if 'phone-verification' in form_actions:
        return True
    inputs = state.get('inputs') or []
    attrs = ' '.join(' '.join(str(i.get(k) or '') for k in ('type','name','id','autocomplete','placeholder')) for i in inputs).lower()
    body = str(state.get('bodyText') or '').lower()
    has_code_input = 'one-time-code' in attrs or 'otp' in attrs or 'code' in attrs
    phone_hint = (
        'phone' in url or 'phone' in form_actions
        or 'check your phone' in body
        or 'verification code we just sent' in body
        or 'enter the verification code' in body and ('text message' in body or 'phone' in body)
        or 'resend text message' in body
        or 'sent to +' in body
    )
    return bool(phone_hint and has_code_input)


def _is_phone_code_page(driver) -> bool:
    return _is_phone_code_state(_phone_page_state(driver))


def _is_add_phone_page(driver) -> bool:
    state = _phone_page_state(driver)
    url = str(state.get('url') or '').lower()
    inputs = state.get('inputs') or []
    attrs = ' '.join(' '.join(str(i.get(k) or '') for k in ('type','name','id','autocomplete')) for i in inputs).lower()
    return 'add-phone' in url or 'type tel' in attrs or 'phone' in attrs or 'tel' in attrs


_PHONE_INPUT_SELECTORS = [
    "input[type='tel']",
    "input[name='phone']",
    "input[name='phone_number']",
    "input[autocomplete='tel']",
    "input[id*='phone']",
    "input[placeholder*='Phone']",
    "input[placeholder*='phone']",
]


def _has_strict_add_phone_form(driver) -> bool:
    try:
        return bool(driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const form = document.querySelector('form[action*="/add-phone" i]')
          || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
        if (!form) return false;
        return !![...form.querySelectorAll('input[type="tel"], input[name="__reservedForPhoneNumberInput_tel"], input[autocomplete="tel"], input[name="phone"], input[name="phone_number"]')].find(visible);
        """))
    except Exception:
        return False


def _auth_origin(driver) -> str:
    try:
        parsed = urlparse(str(driver.current_url or ""))
        if parsed.scheme and parsed.netloc and parsed.hostname and parsed.hostname.endswith("openai.com"):
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    return "https://auth.openai.com"


def _ensure_add_phone_input(driver, *, reason: str = ""):
    """Make sure the current page is back on add-phone and return the phone number input box.

    When switching numbers, if still on the phone-verification/OTP page, we must go back to the phone number page first,
    then write the new number into the page again and resubmit.
    """
    if _has_strict_add_phone_form(driver):
        return _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=2)

    current = str(getattr(driver, "current_url", "") or "")
    if "email-verification" in current.lower():
        logger.info("[Codex][Browser] Currently still on email-verification, first wait for the authorization flow to redirect automatically, to avoid invalid_auth_step")
        _wait_after_email_otp_submit(driver, timeout=45)
        if _has_strict_add_phone_form(driver):
            return _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=2)
        current = str(getattr(driver, "current_url", "") or "")

    target = _auth_origin(driver).rstrip("/") + "/add-phone"
    logger.info(
        "[Codex][Browser] Currently not on the phone number input page, preparing to re-open add-phone and switch numbers:reason=%s url=%s target=%s",
        reason or "retry", current, target,
    )
    try:
        driver.get(target)
        human_delay("navigate")
        return _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=10)
    except Exception as first_exc:
        # Some flows do not allow opening /add-phone directly, so try the browser back to the previous page.
        logger.info("[Codex][Browser] Opening add-phone directly did not get the input box, trying history back:%s", str(first_exc)[:160])
        try:
            driver.back()
            human_delay("navigate")
            return _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=8)
        except Exception as back_exc:
            raise RuntimeError(
                f"Cannot go back to the phone number input page to switch numbers again: direct={type(first_exc).__name__}: {first_exc}; "
                f"back={type(back_exc).__name__}: {back_exc}; state={_phone_page_state(driver)}"
            )


def _set_phone_value(driver, phone: str, *, timeout: int = 10) -> dict:
    """Fill in the add-phone form following step 9 of FlowPilot.

    Key points:
    - All elements are scoped to form[action*="/add-phone"];
    - Write the "number the page expects to display" into the visible tel input box;
    - 如果页面存在隐藏 input[name="phoneNumber"]，同步写入完整 E.164 号码；
    - Trigger input/change and blur so React/React-Aria completes the validation.
    """
    if not _has_strict_add_phone_form(driver):
        raise RuntimeError(f"The current page is not the add-phone phone number input page, the phone number cannot be filled in: state={_phone_page_state(driver)}")
    result = driver.execute_script(r"""
    const rawPhone = String(arguments[0] || '').trim();
    const e164 = rawPhone.startsWith('+') ? rawPhone : ('+' + rawPhone.replace(/\D+/g, ''));
    const digits = e164.replace(/\D+/g, '');
    const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
    const form = document.querySelector('form[action*="/add-phone" i]')
      || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
    if (!form) {
      return {ok:false, error:'missing_add_phone_form', url: location.href};
    }
    const phoneInput = [...form.querySelectorAll('input[type="tel"], input[name="__reservedForPhoneNumberInput_tel"], input[autocomplete="tel"], input[name="phone"], input[name="phone_number"]')]
      .find(visible);
    if (!phoneInput) {
      return {ok:false, error:'missing_phone_input', url: location.href};
    }

    const hiddenPhoneNumberInput = form.querySelector('input[name="phoneNumber"]');
    const select = form.querySelector('select');
    let dialCode = '';
    let selectedText = '';
    let selectedChanged = false;
    const optionDialCode = (opt) => {
      const text = String(opt?.textContent || opt?.label || opt?.value || '').replace(/\s+/g, ' ').trim();
      const m = text.match(/\+(\d{1,4})\b/);
      return m ? m[1] : '';
    };
    if (select) {
      // Following FlowPilot ensureCountrySelected: select the corresponding country/area code by the number prefix, to avoid a default country that does not match the number.
      const options = [...select.options];
      const matched = options
        .map(opt => ({opt, code: optionDialCode(opt)}))
        .filter(x => x.code && digits.startsWith(x.code))
        .sort((a, b) => b.code.length - a.code.length)[0];
      if (matched && select.value !== matched.opt.value) {
        select.value = matched.opt.value;
        select.dispatchEvent(new Event('input', {bubbles:true}));
        select.dispatchEvent(new Event('change', {bubbles:true}));
        selectedChanged = true;
      }
      if (select.selectedIndex >= 0 && select.options[select.selectedIndex]) {
        const opt = select.options[select.selectedIndex];
        selectedText = String(opt.textContent || opt.label || opt.value || '').replace(/\s+/g, ' ').trim();
        dialCode = optionDialCode(opt);
      }
    }

    // FlowPilot: the visible box usually gets the national number; the hidden phoneNumber gets the full E.164.
    // If the page area code cannot be determined, the visible box gets the full +E164, to avoid losing the country code.
    let visibleValue = e164;
    if (dialCode && digits.startsWith(dialCode) && digits.length > dialCode.length + 3) {
      visibleValue = digits.slice(dialCode.length);
      if (!visibleValue) visibleValue = e164;
    }

    const setNativeValue = (el, value) => {
      const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      el.focus();
      if (setter) setter.call(el, ''); else el.value = '';
      el.dispatchEvent(new Event('input', {bubbles:true}));
      el.dispatchEvent(new Event('change', {bubbles:true}));
      if (setter) setter.call(el, value); else el.value = value;
      el.dispatchEvent(new Event('input', {bubbles:true}));
      el.dispatchEvent(new Event('change', {bubbles:true}));
    };

    phoneInput.scrollIntoView({block:'center'});
    setNativeValue(phoneInput, visibleValue);
    if (hiddenPhoneNumberInput) {
      hiddenPhoneNumberInput.value = e164;
      hiddenPhoneNumberInput.dispatchEvent(new Event('input', {bubbles:true}));
      hiddenPhoneNumberInput.dispatchEvent(new Event('change', {bubbles:true}));
    }
    phoneInput.blur();
    document.body?.focus?.();
    return {
      ok: true,
      e164,
      visibleValue,
      actualVisible: phoneInput.value || '',
      hiddenValue: hiddenPhoneNumberInput ? (hiddenPhoneNumberInput.value || '') : '',
      dialCode,
      selectedText,
      selectedChanged,
      inputName: phoneInput.getAttribute('name') || '',
      inputId: phoneInput.id || '',
      url: location.href,
    };
    """, phone)
    if not result or not result.get("ok"):
        raise RuntimeError(f"Writing the phone number failed result={result} state={_phone_page_state(driver)}")
    actual = str(result.get("actualVisible") or "").strip()
    visible_value = str(result.get("visibleValue") or "").strip()
    hidden_value = str(result.get("hiddenValue") or "").strip()
    e164 = str(result.get("e164") or "").strip()
    # OpenAI/React-Aria The phone box formats automatically, e.g. +84925154291 -> +84 925 154 291.
    # It cannot be compared exactly as UI strings; only the digit-normalized values are compared.
    actual_digits = ''.join(ch for ch in actual if ch.isdigit())
    visible_digits = ''.join(ch for ch in visible_value if ch.isdigit())
    e164_digits = ''.join(ch for ch in e164 if ch.isdigit())
    hidden_digits = ''.join(ch for ch in hidden_value if ch.isdigit())
    expected_visible_ok = bool(actual_digits) and (actual_digits == visible_digits or actual_digits == e164_digits)
    if not expected_visible_ok:
        raise RuntimeError(f"Validation of the visible phone number input box failed expected_digits={visible_digits or e164_digits} actual={actual} result={result} state={_phone_page_state(driver)}")
    if hidden_value and hidden_digits != e164_digits:
        raise RuntimeError(f"Validation of the hidden phone number field failed expected={e164} actual={hidden_value} result={result} state={_phone_page_state(driver)}")
    return result


def _blur_active_input_and_wait(driver, *, label: str = "input completed") -> None:
    """After typing the phone number, move focus away and give the front-end validation / formatting time to process."""
    try:
        driver.execute_script(r"""
        const active = document.activeElement;
        if (active && typeof active.blur === 'function') active.blur();
        document.body?.focus?.();
        document.dispatchEvent(new Event('change', {bubbles:true}));
        """)
    except Exception:
        pass
    seconds = random.uniform(1.8, 3.2)
    logger.info("[Codex][Browser] %s, focus moved away, waiting %.1f seconds for the page to process", label, seconds)
    time.sleep(seconds)


def _verify_add_phone_value_before_submit(driver, expected_e164: str) -> dict:
    result = driver.execute_script(r"""
    const expected = String(arguments[0] || '').trim();
    const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
    const form = document.querySelector('form[action*="/add-phone" i]')
      || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
    if (!form) return {ok:false, error:'missing_add_phone_form', url: location.href};
    const input = [...form.querySelectorAll('input[type="tel"], input[name="__reservedForPhoneNumberInput_tel"], input[autocomplete="tel"], input[name="phone"], input[name="phone_number"]')].find(visible);
    const hidden = form.querySelector('input[name="phoneNumber"]');
    const visibleValue = String(input?.value || '').trim();
    const hiddenValue = String(hidden?.value || '').trim();
    const digits = value => String(value || '').replace(/\D+/g, '');
    const visibleDigits = digits(visibleValue);
    const hiddenDigits = digits(hiddenValue);
    const expectedDigits = digits(expected);
    // The input box may be formatted automatically, so compare by digits; the hidden field, if present, must equal the full E.164.
    const ok = !!visibleDigits && visibleDigits === expectedDigits && (!hidden || hiddenDigits === expectedDigits);
    return {ok, visibleValue, hiddenValue, expected, visibleDigits, hiddenDigits, expectedDigits, url: location.href};
    """, expected_e164)
    if not result or not result.get("ok"):
        raise RuntimeError(f"Validation before submitting the phone number failed result={result} state={_phone_page_state(driver)}")
    return result


def _wait_page_settle_after_submit() -> None:
    """After clicking submit, first wait for the page to process, then check the send status."""
    seconds = random.uniform(2.0, 4.0)
    logger.info("[Codex][Browser] Clicked submit, waiting %.1f seconds for the page to send / redirect, then checking the state", seconds)
    time.sleep(seconds)


def _refresh_add_phone_for_retry(driver, *, reason: str = "") -> None:
    """Refresh the phone number page after a send failure / before switching numbers, to avoid leftover old error state and old numbers."""
    try:
        logger.info("[Codex][Browser] Send failed / preparing to switch numbers, refreshing the phone number page:%s", reason or "retry")
        driver.refresh()
        human_delay("navigate")
        try:
            _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=8)
            return
        except Exception:
            pass
        # If after the refresh we are still not on the input page, force going back to add-phone.
        target = _auth_origin(driver).rstrip("/") + "/add-phone"
        logger.info("[Codex][Browser] Phone number input box not found after the refresh, re-opening:%s", target)
        driver.get(target)
        human_delay("navigate")
        _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=8)
    except Exception as exc:
        logger.info("[Codex][Browser] Refreshing the phone number page failed, the next round will try to go back to add-phone again:%s", str(exc)[:180])


def _click_add_phone_continue_button(driver, *, timeout: int = 10) -> dict:
    """Click the Continue button in the add-phone form.

    Following getAddPhoneSubmitButton + simulateClick of FlowPilot: prefer finding it inside the add-phone form
    enabled submit, and fall back to form.requestSubmit(button) when the click fails.
    """
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            btn = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
            const enabled = el => {
              if (!el) return false;
              if (el.disabled) return false;
              if (String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true') return false;
              return true;
            };
            const form = document.querySelector('form[action*="/add-phone" i]')
              || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
            if (!form) return null;
            const buttons = [...form.querySelectorAll('button[type="submit"], input[type="submit"]')];
            return buttons.find(b => visible(b) && enabled(b) && (b.getAttribute('data-dd-action-name') || '').toLowerCase() === 'continue')
              || buttons.find(b => visible(b) && enabled(b))
              || buttons.find(b => visible(b))
              || null;
            """)
            if btn:
                driver.execute_script("arguments[0].scrollIntoView({block:'center'});", btn)
                time.sleep(random.uniform(0.3, 0.8))
                try:
                    text = str(getattr(btn, 'text', '') or btn.get_attribute('value') or btn.get_attribute('data-dd-action-name') or '').strip()
                except Exception:
                    text = ''
                try:
                    btn.click()
                    _wait_page_settle_after_submit()
                    return {"ok": True, "method": "click", "text": text}
                except Exception as click_exc:
                    last = click_exc
                    submitted = driver.execute_script(r"""
                    const btn = arguments[0];
                    const form = btn?.form || btn?.closest?.('form');
                    if (form && typeof form.requestSubmit === 'function') {
                      form.requestSubmit(btn);
                      return true;
                    }
                    if (btn && typeof btn.click === 'function') {
                      btn.click();
                      return true;
                    }
                    return false;
                    """, btn)
                    if submitted:
                        _wait_page_settle_after_submit()
                        return {"ok": True, "method": "requestSubmit", "text": text, "click_error": str(click_exc)[:160]}
        except Exception as exc:
            last = exc
        time.sleep(0.25)
    raise RuntimeError(f"submit_missing: add-phone Continue/Continue submit button not found last={last} state={_phone_page_state(driver)}")


def _force_submit_add_phone_form(driver) -> dict:
    """add-phone When the page button click has no effect, call requestSubmit directly on the current form."""
    try:
        return driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const form = document.querySelector('form[action*="/add-phone" i]')
          || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
        if (!form) return {ok:false, reason:'missing_form', url: location.href};
        const btn = [...form.querySelectorAll('button[type="submit"],input[type="submit"]')]
          .find(el => visible(el) && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true')
          || form.querySelector('button[type="submit"],input[type="submit"]');
        if (btn) btn.scrollIntoView({block:'center'});
        if (typeof form.requestSubmit === 'function') form.requestSubmit(btn || undefined);
        else if (btn && typeof btn.click === 'function') btn.click();
        else form.submit();
        return {ok:true, method: btn ? 'requestSubmit(button)' : 'requestSubmit(form)', url: location.href};
        """) or {}
    except Exception as exc:
        return {ok:false, reason:f'{type(exc).__name__}: {exc}', url:getattr(driver, 'current_url', '')}


def _wait_after_phone_send(driver, timeout: int = 12) -> str:
    end = time.time() + timeout
    last = {}
    force_submitted = False
    while time.time() < end:
        time.sleep(1)
        last = _phone_page_state(driver)
        # The verification code page must be judged first: the page wording may contain words such as send/limit/check, so it must not
        # “Check your phone / Enter the verification code...” be misjudged as a send failure like "Check your phone / Enter the verification code...".
        if _is_phone_code_state(last):
            return 'code_page'
        body = str(last.get('bodyText') or '')
        reason = _classify_phone_page_failure(last)
        if reason:
            raise RuntimeError(f"{reason}: {body[:240]}")
        # Still on add-phone and a field has aria-invalid: the number is considered rejected.
        if _is_add_phone_page(driver):
            invalid = any(str(i.get('ariaInvalid') or '').lower() == 'true' for i in (last.get('inputs') or []))
            if invalid:
                raise RuntimeError(f"invalid_phone: add-phone input aria-invalid state={last}")
            # Cloak/React-Aria In some scenarios btn.click may only focus without triggering the form submit; do one more requestSubmit.
            if not force_submitted and time.time() > end - timeout + 3:
                info = _force_submit_add_phone_form(driver)
                logger.info("[Codex][Browser] add-phone Still on this page after the click, additionally running form.requestSubmit:%s", info)
                force_submitted = True
                time.sleep(2)
    if _is_phone_code_state(last) or _is_phone_code_page(driver):
        return 'code_page'
    if _is_add_phone_page(driver):
        raise RuntimeError(f"send_not_accepted: Still on add-phone after the submit, state add-phone state={last}")
    return 'unknown'


def _wait_after_phone_otp_submit(driver, timeout: int = 20) -> str:
    """Wait for the result after the phone verification code is submitted.

    On success it usually leaves phone-verification and enters consent/workspace/callback; after the submit we must not
    3 read the old page wording immediately and judge a failure as send_limited. Only when it is clearly still in the phone number flow and an error appears
    do we return a failure.
    """
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        time.sleep(1)
        current = str(getattr(driver, "current_url", "") or "")
        if _is_callback_url(current):
            return "callback"
        last = _phone_page_state(driver)
        # Left the phone verification code / add-phone pages, which means the verification code was accepted; the rest is handed to the consent/callback flow.
        if not _is_phone_code_state(last) and not _is_add_phone_page(driver):
            return "left_phone_flow"
        # While still on the verification code page, only clear errors count as failures; an ordinary Check your phone page keeps waiting.
        if _is_phone_code_state(last):
            inputs = last.get('inputs') or []
            invalid = any(str(i.get('ariaInvalid') or '').lower() == 'true' for i in inputs)
            body = str(last.get('bodyText') or '').lower()
            if invalid or any(k in body for k in (
                'invalid code', 'incorrect code', 'wrong code', 'expired code',
                'code is invalid', 'code was invalid', '验证码无效', '验证码错误', '验证码已过期',
                '認証コードが無効', 'コードが正しく',
            )):
                raise RuntimeError(f"invalid_phone_code: {(last.get('bodyText') or '')[:240]}")
            continue
        reason = _classify_phone_page_failure(last)
        if reason:
            raise RuntimeError(f"{reason}: {(last.get('bodyText') or '')[:240]}")
    # Check once more after the timeout: if the phone number flow has been left, count it as passed; if still on the verification code page without a clear error, leave it to the following flow to keep trying.
    current = str(getattr(driver, "current_url", "") or "")
    if _is_callback_url(current):
        return "callback"
    last = _phone_page_state(driver)
    if not _is_phone_code_state(last) and not _is_add_phone_page(driver):
        return "left_phone_flow"
    if _is_phone_code_state(last):
        return "still_code_page"
    return "unknown"


def _classify_phone_page_failure(state: dict) -> str:
    if _is_phone_code_state(state):
        return ''
    # WhatsApp Judge by the DOM radio value; other send failures fall back to the server/page error text.
    radios = state.get('radios') or []
    if any('whatsapp' in str(r.get('value','')).lower().replace(' ', '') and r.get('checked') for r in radios):
        return 'whatsapp_channel'
    text = str(state.get('bodyText') or '').lower()
    if 'invalid_auth_step' in text or 'invalid auth step' in text:
        return 'invalid_auth_step'
    if 'whatsapp' in text or 'whats app' in text:
        return 'whatsapp_channel'
    if any(k in text for k in ('invalid phone', 'not a valid phone', 'phone number is not valid', '号码无效', '手机号无效')):
        return 'invalid_phone'
    if any(k in text for k in (
        'cannot send', 'could not send', 'unable to send', 'failed to send', 'send failed',
        '发送失败', '发送失败了', '无法发送', '不能发送', '无法向',
        '送信できません', '送信に失敗', '送信できなかった',
    )):
        return 'delivery_refused'
    if any(k in text for k in ('too many', 'rate limit', 'throttle', '频繁', '限流')):
        return 'send_limited'
    return ''

def _sleep_before_phone_retry(attempt: int, max_retries: int, *, prefix: str = "[Codex][Browser]") -> None:
    """Wait a random time before switching numbers, at least 3 seconds, to avoid submitting numbers too quickly in a row."""
    if attempt >= max_retries:
        return
    seconds = random.uniform(3.0, 8.0)
    logger.info("%s Waiting a random %.1f seconds before switching numbers", prefix, seconds)
    time.sleep(seconds)


def _do_phone_verification_if_present(driver) -> None:
    """If the page requires phone number verification, complete it automatically with the current sms_provider."""
    provider = str(getattr(sms_provider._cfg, "SMS_PROVIDER", "") or "").strip().lower() if hasattr(sms_provider, "_cfg") else ""
    http = sms_provider._http()
    max_retries = int(getattr(sms_provider._cfg, "SMS_MAX_RETRIES", 10) or 10) if hasattr(sms_provider, "_cfg") else 10
    try:
        # If the page has no phone number input box, return directly.
        try:
            end_detect = time.time() + 8
            while time.time() < end_detect and not _has_strict_add_phone_form(driver):
                # If already on the verification code page, the phone step was submitted before; keep handling the verification code page and do not skip it.
                if _is_phone_code_page(driver):
                    break
                time.sleep(0.5)
            if not (_has_strict_add_phone_form(driver) or _is_phone_code_page(driver)):
                raise RuntimeError("not_phone_flow")
        except Exception:
            logger.info("[Codex][Browser] Phone number verification page not detected, skipping the phone step")
            return

        last_err = None
        for attempt in range(1, max_retries + 1):
            activation_id = None
            try:
                activation_id, phone = sms_provider.acquire_number(http)
                logger.info("[Codex][Browser] Phone verification attempt %s/%s, provider=%s, number=+%s", attempt, max_retries, provider, phone)
                logger.info("[Codex][Browser] Preparing the phone number input page, setting a new phone number again")
                _ensure_add_phone_input(driver, reason=f"attempt-{attempt}")
                phone_fill = _set_phone_value(driver, f"+{phone}", timeout=10)
                logger.info(
                    "[Codex][Browser] Phone number set again:e164=%s visible=%s hidden=%s dialCode=%s country=%s",
                    phone_fill.get("e164"), phone_fill.get("actualVisible"), phone_fill.get("hiddenValue") or "-",
                    phone_fill.get("dialCode") or "-", (str(phone_fill.get("selectedText") or "-") + (" [changed]" if phone_fill.get("selectedChanged") else "")),
                )
                _blur_active_input_and_wait(driver, label="phone number input completed")
                phone_verify = _verify_add_phone_value_before_submit(driver, str(phone_fill.get("e164") or f"+{phone}"))
                logger.info("[Codex][Browser] Validation before the phone number submit passed:visible=%s hidden=%s", phone_verify.get("visibleValue"), phone_verify.get("hiddenValue") or "-")
                logger.info("[Codex][Browser] Checking and selecting the SMS text message channel")
                _select_sms_channel_or_raise(driver)
                _blur_active_input_and_wait(driver, label="SMS channel confirmation completed")
                submit_info = _click_add_phone_continue_button(driver, timeout=10)
                logger.info("[Codex][Browser] Clicked the phone number Continue button: %s, waiting to enter the SMS verification code page", submit_info)
                _wait_page_settle_after_submit()

                # Wait for the page to enter phone-verification; if the number is invalid / cannot be sent / WhatsApp channel, switch numbers immediately.
                _wait_after_phone_send(driver, timeout=15)
                logger.info("[Codex][Browser] Entered the phone verification code page")

                sms_provider.set_status(activation_id, 1, http=http)
                logger.info(
                    "[Codex][Browser] SMS sent, starting to poll for the verification code activation_id=%s wait=%ss interval=%ss",
                    activation_id, sms_provider._cfg.SMS_CODE_WAIT, sms_provider._cfg.SMS_POLL_INTERVAL
                )
                sms_code = sms_provider.wait_for_sms_code(activation_id, http)
                logger.info("[Codex][Browser] Phone OTP received:%s", sms_code)
                _type_otp(driver, sms_code)
                logger.info("[Codex][Browser] Filled in the phone OTP")
                human_delay("otp_input")
                if not _click_if_present(driver, ["button[type='submit']", "input[type='submit']"], timeout=10):
                    raise RuntimeError(f"verify_submit_missing: phone verification submit not found state={_phone_page_state(driver)}")
                logger.info("[Codex][Browser] Phone OTP submitted, waiting for the verification result")
                otp_outcome = _wait_after_phone_otp_submit(driver, timeout=25)
                logger.info("[Codex][Browser] State after submitting the phone OTP:%s", otp_outcome)
                sms_provider.complete(activation_id, http)
                return
            except Exception as exc:
                last_err = exc
                err_text = str(exc) or ""
                logger.warning("[Codex][Browser] Phone verification attempt failed, switching numbers:%s", err_text[:240])
                if activation_id:
                    try:
                        sms_provider.cancel(activation_id, http)
                    except Exception:
                        pass
                # Insufficient balance / no available numbers: no number of retries will succeed, so fail immediately to stop the loss,
                # avoiding waiting in vain for N rounds of number switching and retries (each round also refreshes the page + waits randomly).
                if any(k in err_text for k in (
                    "NO_BALANCE", "NO_NUMBERS", "BALANCE", "余额不足",
                    "暂无可用号码", "没有可用号码", "insufficient", "not enough balance",
                )):
                    raise RuntimeError(
                        f"The code-receiving platform has insufficient balance or no available numbers, number switching was stopped to stop the loss:{err_text[:180]}"
                    ) from exc
                if "invalid_auth_step" in str(exc):
                    raise RuntimeError(
                        "The phone number flow entered invalid_auth_step, which means the authorization state has not moved on from email-verification normally or has become invalid;"
                        "stopped switching numbers, to avoid continuing to consume numbers"
                    ) from exc
                # If the phone number / verification code related pages have been left, count it as passed or no longer needed;
                # if still on phone-verification, the next round must go back to add-phone to fill in a new number again and submit.
                try:
                    if _is_phone_code_page(driver):
                        logger.info("[Codex][Browser] Still on the phone verification code page, the next round will return to add-phone to set a new number again")
                    else:
                        _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=2)
                except Exception:
                    if _is_add_phone_page(driver) or _is_phone_code_page(driver):
                        logger.info("[Codex][Browser] Still in the phone number flow, continuing to switch numbers and retry")
                    else:
                        logger.info("[Codex][Browser] The phone input page has disappeared, continuing with the following flow")
                        return
                if attempt < max_retries:
                    _refresh_add_phone_for_retry(driver, reason=str(exc)[:120])
                _sleep_before_phone_retry(attempt, max_retries)
        raise RuntimeError(f"Roxy Phone verification still failed after {max_retries} retries, last error:{last_err}")
    finally:
        try:
            http.close()
        except Exception:
            pass


def _finish_consent_workspace(driver) -> str:
    """Click the continue/allow button on the Codex consent/workspace page until the callback."""
    end = time.time() + int(_roxy_cfg.ROXY_CODEX_CALLBACK_TIMEOUT)
    while time.time() < end:
        callback = _extract_callback_url_from_any_window(driver)
        if callback:
            return callback
        current = str(driver.current_url or "")
        clicked = False
        for selectors in [
            ["//button[contains(., 'Allow')]", "//button[contains(., 'Authorize')]", "//button[contains(., 'Continue')]"],
            ["//button[contains(., 'Select')]", "//button[contains(., 'Use workspace')]", "//button[contains(., 'Confirm')]"],
            ["//button[contains(., '允许')]", "//button[contains(., '授权')]", "//button[contains(., '继续')]", "//button[contains(., '确认')]"],
            ["button[type='submit']"],
        ]:
            if _click_if_present(driver, selectors, timeout=2):
                clicked = True
                human_delay("form")
                break
        if not clicked:
            time.sleep(0.8)
    return _wait_for_callback(driver, timeout=5)




def clear_roxy_browser_auth_state(driver) -> None:
    """Clear the OpenAI/ChatGPT login state and cache in the current Roxy browser, so the same environment can be reused to run Codex after registration."""
    origins = [
        "https://auth.openai.com",
        "https://chatgpt.com",
        "https://openai.com",
        "https://platform.openai.com",
    ]
    logger.info("[Codex][Browser] Reusing the registration window: starting to clean Cookie / localStorage / sessionStorage / cache")
    try:
        driver.execute_cdp_cmd("Network.enable", {})
    except Exception:
        pass
    try:
        driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
        logger.info("[Codex][Browser] Cleaned the browser Cookie")
    except Exception as exc:
        logger.info("[Codex][Browser] Cleaning Cookies failed, continuing to try other caches:%s", str(exc)[:160])
    try:
        driver.execute_cdp_cmd("Network.clearBrowserCache", {})
        logger.info("[Codex][Browser] Cleaned the browser Cache")
    except Exception as exc:
        logger.info("[Codex][Browser] Cleaning the Cache failed, continuing:%s", str(exc)[:160])
    for origin in origins:
        try:
            driver.execute_cdp_cmd("Storage.clearDataForOrigin", {
                "origin": origin,
                "storageTypes": "all",
            })
            logger.info("[Codex][Browser] Cleaned the site data:%s", origin)
        except Exception as exc:
            logger.debug("[Codex][Browser] Cleaning the site data failed %s: %s", origin, exc)
    try:
        driver.get("about:blank")
    except Exception:
        pass
    time.sleep(1.0)
    logger.info("[Codex][Browser] Registration window login state cleaned, preparing to start the Codex authorization")

def _run_roxy_codex_oauth_once(
    email: str,
    otp_provider=None,
    proxy: str | None = None,
    force: bool = False,
    existing_driver=None,
    existing_opened=None,
    reuse_existing_profile: bool = False,
    clear_existing_state: bool = True,
) -> dict:
    """Fingerprint browser Codex OAuth entry point.

    existing_driver/existing_opened Used for "run Codex right after a successful registration":
    Reuse the Roxy window used for registration, do not create a new environment, and only start the authorization after cleaning the browser state.
    """
    from core import codex_oauth as proto

    if not force and not proto._cfg.ENABLE_CODEX_AUTO:
        return proto._codex_result(status="skipped", message="ENABLE_CODEX_AUTO=False")
    if not email:
        return proto._codex_result(status="skipped", message="email is empty")
    if otp_provider is None:
        otp_provider = wait_for_otp

    client = None if reuse_existing_profile else RoxyBrowserClient()
    opened = existing_opened if reuse_existing_profile else client.open_profile()
    browser_kind_token = _CODEX_BROWSER_KIND.set(_detect_browser_kind(opened))
    driver = existing_driver if reuse_existing_profile else None
    owns_driver = not reuse_existing_profile
    try:
        auth_source = proto._codex_auth_url_source()
        code_verifier = None
        if auth_source == "cpa":
            cpa_auth = proto._request_cpa_authorize_url()
            state = cpa_auth["state"]
            auth_url = cpa_auth["auth_url"]
            logger.info("[Codex][Browser] Currently using the CPA authorization URL: %s", auth_url)
        elif auth_source == "sub2":
            sub2_auth = proto._request_sub2_authorize_url()
            state = sub2_auth["state"]
            auth_url = sub2_auth["auth_url"]
            logger.info("[Codex][Browser] Currently using the sub2 authorization URL: %s", auth_url)
        elif auth_source == "local":
            code_verifier, code_challenge = proto._generate_pkce()
            state = proto._generate_state()
            auth_url = proto._build_authorize_url(state, code_challenge, prompt="login")
            logger.info("[Codex][Browser] Currently using the local PKCE authorization URL: %s", auth_url)
        else:
            raise RuntimeError(f"[Codex][Browser] unsupported CODEX_AUTH_URL_SOURCE={auth_source!r}")

        if not driver:
            driver = _build_driver(opened)
            _center_browser_window(driver)
        driver.set_page_load_timeout(int(_roxy_cfg.ROXY_SELENIUM_TIMEOUT))
        logger.info("[Codex][Browser] Starting authorization: %s, profile=%s,reuse_existing_profile=%s", email, opened.profile_id, reuse_existing_profile)
        if reuse_existing_profile and clear_existing_state:
            clear_roxy_browser_auth_state(driver)

        _fill_email_and_otp(driver, email, otp_provider, auth_url)
        human_delay("api")
        logger.info("[Codex][Browser] Checking whether phone number verification is needed")
        _do_phone_verification_if_present(driver)
        logger.info("[Codex][Browser] Phone verification handled / not needed, waiting for the authorization confirmation and callback")
        callback_url = _finish_consent_workspace(driver)
        code = proto._extract_code(callback_url, state)
        logger.info("[Codex][Browser] Captured the callback code:%s...", code[:24])

        if auth_source == "cpa":
            submit_payload = proto._submit_cpa_callback(callback_url)
            path = proto._save_cpa_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url,
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "CPA callback submitted"
            return proto._codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=f"{_codex_driver_name()}: {msg}",
            )

        if auth_source == "sub2":
            submit_payload = proto._submit_sub2_callback(
                callback_url,
                session_id=(sub2_auth or {}).get("session_id", ""),
                redirect_uri=(proto.parse_qs(proto.urlparse(auth_url or "").query).get("redirect_uri") or [""])[0],
            )
            path = proto._save_sub2_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url,
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "sub2 callback uploaded"
            return proto._codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=f"{_codex_driver_name()}: {msg}",
            )

        if not code_verifier:
            raise RuntimeError("[Codex][Browser] local mode is missing code_verifier")
        session = proto.BrowserSession(proxy=proxy, fingerprint_seed=f"account:{email.lower()}")
        token_resp = proto.exchange_codex_token(session, code, code_verifier)
        id_claims = proto._parse_id_token(token_resp.get("id_token", ""))
        effective_email = id_claims.get("email") or email
        storage = proto.build_codex_storage(token_resp, id_claims)
        path = proto.save_codex_credential(storage, effective_email, id_claims.get("plan_type", ""))
        return proto._codex_result(
            status="success",
            ok=True,
            email=effective_email,
            file_path=str(path),
            callback_url=callback_url,
            message=f"{_codex_driver_name()} plan={id_claims.get('plan_type') or 'unknown'}",
        )
    except AccountUnusableError as exc:
        logger.warning("[Codex][Browser] Account is dead: %s,%s", email, exc.error_code)
        return proto._codex_result(
            status="deactivated",
            email=email,
            message=f"Account is dead ({exc.error_code or 'account_deactivated'})",
        )
    except Exception as exc:
        logger.warning("[Codex][Browser] Failed: %s,%s: %s", email, type(exc).__name__, str(exc)[:240])
        logger.debug("[Codex][Browser] failure details", exc_info=True)
        return proto._codex_result(status="failed", email=email, message=f"{type(exc).__name__}: {str(exc)[:220]}")
    finally:
        # When the window is reused after registration, the driver/profile lifecycle is cleaned up by the registration flow uniformly,
        # so quit/delete must not be called here, otherwise the registration environment would be destroyed prematurely.
        if owns_driver and driver and not bool(_roxy_cfg.ROXY_KEEP_BROWSER_OPEN):
            try:
                driver.quit()
            except Exception:
                pass
        if owns_driver and client and not bool(_roxy_cfg.ROXY_KEEP_BROWSER_OPEN):
            client.cleanup_profile(opened)
        try:
            _CODEX_BROWSER_KIND.reset(browser_kind_token)
        except Exception:
            pass


def run_roxy_codex_oauth(
    email: str,
    otp_provider=None,
    proxy: str | None = None,
    force: bool = False,
    existing_driver=None,
    existing_opened=None,
    reuse_existing_profile: bool = False,
    clear_existing_state: bool = True,
) -> dict:
    """Fingerprint browser Codex OAuth entry point; when the CPA callback hits a 409 timeout, start a new round of authorization."""
    from core import codex_oauth as proto

    max_rounds = 2
    last_result = None
    for round_no in range(1, max_rounds + 1):
        if round_no > 1:
            logger.warning(
                "[Codex][Browser] CPA callback returned Timeout waiting for OAuth callback, starting Codex authorization round %s/%s again:%s",
                round_no, max_rounds, email,
            )
        result = _run_roxy_codex_oauth_once(
            email=email,
            otp_provider=otp_provider,
            proxy=proxy,
            force=force,
            existing_driver=existing_driver,
            existing_opened=existing_opened,
            reuse_existing_profile=reuse_existing_profile,
            clear_existing_state=clear_existing_state,
        )
        last_result = result
        if result.get("ok"):
            return result
        msg = result.get("message") or result.get("error") or ""
        if not proto._is_cpa_callback_reauth_error(msg):
            return result
    if last_result:
        last_result = dict(last_result)
        last_result["message"] = f"CPA callback timed out, re-authorized for {max_rounds} rounds and still failed:{last_result.get('message') or ''}"
        return last_result
    return proto._codex_result(status="failed", email=email, message="CPA callback timed out, re-authorization failed")
