# -*- coding: utf-8 -*-
"""
Browser Use Cloud + Playwright registration driver.

Goals:
  - does not depend on a local RoxyBrowser
  - Complete the ChatGPT registration through Browser Use stealth Chromium + optional residential proxy
  - Reuse the email OTP / account persistence logic of this repository
  - Codex is not run by default (can be hooked up later when needed)
"""
from __future__ import annotations

import logging
import random
import threading
import string
import time
from datetime import date
from pathlib import Path
from typing import Any, Callable

from config import browser_use as _cfg
from config import twofa as _twofa_cfg
from core.account_export import save_account_data, _post_register_dwell_seconds
from core.browser_use_client import BrowserUseClient
from core.email_provider import acquire_email_after_input, resolve_email_source, wait_for_otp
from core.humanize import delay as human_delay

logger = logging.getLogger(__name__)

_LOG_CONTEXT = threading.local()


def _log_provider_label() -> str:
    return str(getattr(_LOG_CONTEXT, "provider_label", "BrowserUse") or "BrowserUse")


def _set_log_provider_label(label: str) -> None:
    _LOG_CONTEXT.provider_label = label or "BrowserUse"


def _set_cloud_provider(prefix: str) -> None:
    _LOG_CONTEXT.provider_prefix = prefix or "browser_use"


def _cloud_provider_prefix() -> str:
    return str(getattr(_LOG_CONTEXT, "provider_prefix", "browser_use") or "browser_use")


def _skyvern_human_mode() -> bool:
    if _cloud_provider_prefix() != "skyvern":
        return False
    try:
        from config import skyvern as _skyvern_cfg

        return bool(getattr(_skyvern_cfg, "SKYVERN_HUMAN_MODE", True))
    except Exception:
        return True


class _CloudProviderLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        label = _log_provider_label()
        if label != "BrowserUse" and isinstance(record.msg, str):
            record.msg = record.msg.replace("[BrowserUse]", f"[{label}]").replace("BrowserUse", label)
        return True


logger.addFilter(_CloudProviderLogFilter())


def _fast_mode() -> bool:
    if _skyvern_human_mode():
        return False
    return bool(getattr(_cfg, "BROWSER_USE_FAST_MODE", True))


def _log_timing_enabled() -> bool:
    return bool(getattr(_cfg, "BROWSER_USE_LOG_TIMING", True))


def _cloud_typing_delay(kind: str = "normal") -> tuple[int, int]:
    """Centrally control the human typing speed: characters are visibly typed one by one, but not so slowly that one page takes a minute."""
    if kind == "email":
        return (45, 115) if _fast_mode() else (75, 180)
    if kind == "otp":
        return (35, 80) if _fast_mode() else (55, 120)
    if kind == "name":
        return (55, 130) if _fast_mode() else (85, 200)
    return (55, 140) if _fast_mode() else (90, 220)


def _close_browser_use_session(browser, *, reason: str = "") -> None:
    """Close the CDP session of the Browser Use registration phase.

    Codex OAuth Codex re-opens its own clean session; if Codex runs right after a successful registration,
    the Browser Use session of the registration phase must be disconnected first, so two remote browser sessions do not hold resources at the same time.
    """
    if browser is None:
        return
    label = f":{reason}" if reason else ""
    try:
        logger.info("[BrowserUse] Closing the registration browser session%s", label)
        browser.close()
    except Exception as exc:
        logger.warning("[BrowserUse] Failed to close the registration browser session%s:%s: %s", label, type(exc).__name__, str(exc)[:180])


def _bu_delay(kind: str, seconds: float | None = None) -> None:
    if _fast_mode():
        if seconds is None:
            seconds = {
                "navigate": random.uniform(0.45, 0.95),
                "form": random.uniform(0.35, 0.85),
                "otp_input": random.uniform(0.25, 0.65),
                "api": random.uniform(0.3, 0.8),
                "post_auth": random.uniform(0.6, 1.2),
            }.get(kind, random.uniform(0.15, 0.35))
        if seconds > 0:
            time.sleep(seconds)
        return
    human_delay(kind)


def _human_pause(min_s: float = 0.08, max_s: float = 0.28) -> None:
    """Browser Use / Skyvern Always keep random pauses, to avoid millisecond-level continuous operations."""
    try:
        time.sleep(random.uniform(float(min_s), float(max_s)))
    except Exception:
        time.sleep(0.12)


def _safe_scroll_locator(loc, *, timeout: int = 1800) -> None:
    """Skyvern/Elements on a remote CDP often animate; a timeout of scroll waiting for stable must not abort the flow directly."""
    try:
        loc.scroll_into_view_if_needed(timeout=timeout)
        return
    except Exception as exc:
        logger.debug("[BrowserUse] scroll_into_view_if_needed unstable, using the lightweight scroll fallback:%s", str(exc)[:160])
    try:
        loc.evaluate("el => { try { el.scrollIntoView({block:'center', inline:'center', behavior:'instant'}); } catch(e) {} }")
    except Exception:
        pass


def _human_click_locator(loc, *, timeout: int = 3000) -> None:
    """Playwright locator Humanized click: scroll into the visible area, hover, pause, then click."""
    _safe_scroll_locator(loc, timeout=min(1800, max(700, timeout)))
    _human_pause(0.25, 0.75)
    try:
        loc.hover(timeout=min(1600, max(700, timeout)))
        _human_pause(0.18, 0.55)
    except Exception:
        pass
    try:
        loc.click(timeout=timeout, delay=random.randint(80, 260))
    except Exception as exc:
        # Skyvern Remote pages occasionally wait for stable forever; here we step back to a force click, but still keep the preceding scroll/hover/pause.
        logger.debug("[BrowserUse] Regular click failed, falling back to force click:%s", str(exc)[:160])
        loc.click(timeout=timeout, delay=random.randint(80, 220), force=True)
    _human_pause(0.18, 0.5)


def _human_focus_for_typing(loc, *, timeout: int = 2500) -> None:
    """Input focus: prefer a human-like click; when a Skyvern click hangs, fall back to focus, without filling the value instantly."""
    try:
        _human_click_locator(loc, timeout=timeout)
        return
    except Exception as exc:
        logger.debug("[BrowserUse] Clicking to focus the input failed, using focus to continue keyboard input:%s", str(exc)[:180])
    _safe_scroll_locator(loc, timeout=1200)
    _human_pause(0.15, 0.45)
    try:
        loc.focus(timeout=1200)
        _human_pause(0.12, 0.35)
        return
    except Exception as exc:
        logger.debug("[BrowserUse] locator.focus failed, using DOM focus:%s", str(exc)[:160])
    try:
        loc.evaluate("el => { try { el.scrollIntoView({block:'center', inline:'center', behavior:'instant'}); } catch(e) {} try { el.focus({preventScroll:true}); } catch(e) { el.focus && el.focus(); } }")
        _human_pause(0.12, 0.35)
        return
    except Exception as exc:
        raise RuntimeError(f"The input box cannot be focused: {type(exc).__name__}: {exc}") from exc


def _human_fill_locator(
    page,
    loc,
    value: str,
    *,
    timeout: int = 5000,
    typing_delay_range: tuple[int, int] | None = None,
    per_char: bool = True,
) -> None:
    """Simulate human keyboard input; do not write the form with instant fill/evaluate."""
    text = str(value)
    delay_min, delay_max = typing_delay_range or _cloud_typing_delay("normal")

    def _clear_current() -> None:
        try:
            page.keyboard.press("Meta+A")
            _human_pause(0.04, 0.14)
            page.keyboard.press("Backspace")
            return
        except Exception:
            page.keyboard.press("Control+A")
            _human_pause(0.04, 0.14)
            page.keyboard.press("Backspace")

    def _type_slowly() -> None:
        # Always send character by character, and sleep on the Python side, so the cloud CDP does not compress the whole type string into an instant fill.
        for idx, ch in enumerate(text):
            page.keyboard.type(ch, delay=random.randint(delay_min, delay_max))
            if ch in "@._-+ /":
                _human_pause(0.10, 0.28)
            elif idx and idx % random.randint(6, 10) == 0:
                _human_pause(0.08, 0.22)
            else:
                _human_pause(delay_min / 1000.0, delay_max / 1000.0)

    try:
        _human_focus_for_typing(loc, timeout=2500)
        _clear_current()
        _human_pause(0.08, 0.22)
        _type_slowly()
        return
    except Exception:
        try:
            _safe_scroll_locator(loc, timeout=1200)
            _human_focus_for_typing(loc, timeout=2500)
            _clear_current()
            _human_pause(0.08, 0.22)
            _type_slowly()
            return
        except Exception as exc:
            raise RuntimeError(f"Human-like input failed, the instant fill fallback is forbidden: {type(exc).__name__}: {exc}") from exc


class _StepTimer:
    def __init__(self, label: str):
        self.label = label
        self.t0 = time.perf_counter()
        if _log_timing_enabled():
            logger.info("[BrowserUse][timing] %s started", label)

    def done(self, extra: str = "") -> None:
        if _log_timing_enabled():
            cost = time.perf_counter() - self.t0
            logger.info("[BrowserUse][timing] %s finished %.2fs%s %.2fs%s", self.label, cost, (" " + extra) if extra else "")



def _check_manual_stop() -> None:
    try:
        from core.registration_service import check_stop_requested
        check_stop_requested()
    except ImportError:
        return


def _is_manual_stop_exception(exc: Exception) -> bool:
    return type(exc).__name__ == "StopRequested" or "manual stop" in str(exc)


def _generate_password(length: int = 14) -> str:
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*"
    chars = [
        random.choice(upper),
        random.choice(lower),
        random.choice(digits),
        random.choice(symbols),
    ]
    pool = upper + lower + digits + symbols
    chars.extend(random.choice(pool) for _ in range(max(0, length - len(chars))))
    random.shuffle(chars)
    return "".join(chars)


def _registration_password() -> str:
    try:
        from config import register as _register_cfg
        configured = str(getattr(_register_cfg, "REGISTER_PASSWORD", "") or "").strip()
        if configured:
            return configured
    except Exception:
        pass
    return _generate_password()


def _timeout_ms(seconds: int | None = None) -> int:
    value = int(seconds or getattr(_cfg, "BROWSER_USE_TIMEOUT", 90) or 90)
    return max(5, value) * 1000


def _build_playwright_stealth(provider_prefix: str, *, label: str):
    """Build the default enhanced playwright-stealth.

    Browser Use / Skyvern Cloud browsers usually already have a basic stealth fingerprint; here we apply on top by default
    playwright-stealth init scripts, and keep UA / Client Hints / WebGL unoverridden, to avoid messing up
    the native cloud profile.
    """
    try:
        from playwright_stealth import Stealth
    except ImportError:
        logger.warning("[%s] playwright-stealth is missing; please run: uv pip install playwright-stealth --python .venv/bin/python", label)
        return None

    return Stealth(
        # Enhanced by default but without rewriting the native cloud profile.
        navigator_user_agent=False,
        navigator_user_agent_data=False,
        navigator_platform=False,
        sec_ch_ua=False,
        webgl_vendor=False,
        # Enhanced automation-trait corrections.
        chrome_runtime=True,
        chrome_app=True,
        chrome_csi=True,
        chrome_load_times=True,
        hairline=True,
        iframe_content_window=True,
        media_codecs=True,
        navigator_hardware_concurrency=True,
        navigator_languages=True,
        navigator_permissions=True,
        navigator_plugins=True,
        navigator_vendor=True,
        navigator_webdriver=True,
        error_prototype=True,
        
        init_scripts_only=True,
    )


def _apply_cloud_browser_automation_mask(context, page, *, label: str, provider_prefix: str = "browser_use", proxy_country_code: str | None = None) -> dict:
    """Apply playwright-stealth to Browser Use / Skyvern."""
    result: dict[str, Any] = {"playwright_stealth": False}
    stealth = _build_playwright_stealth(provider_prefix, label=label)
    if stealth is None:
        return result
    try:
        stealth.apply_stealth_sync(context)
        result["playwright_stealth"] = True
        logger.info("[%s] Applied to the BrowserContext playwright-stealth", label)
    except Exception as exc:
        logger.debug("[%s] Failed to apply playwright-stealth to the BrowserContext:%s", label, str(exc)[:180])
    try:
        stealth.apply_stealth_sync(page)
        result["playwright_stealth"] = True
        logger.info("[%s] Applied to the current Page playwright-stealth", label)
    except Exception as exc:
        logger.debug("[%s] Failed to apply playwright-stealth to the Page:%s", label, str(exc)[:180])
    return result


def _should_apply_cloud_automation_mask(provider_prefix: str) -> bool:
    # Browser Use / Skyvern All enhancements are applied by default and no extra switch is exposed.
    return True


def _post_register_dwell(page, context, *, provider_prefix: str, email: str) -> None:
    """After a successful registration stay for a random time and then disconnect, simulating a brief look after a manual registration."""
    seconds = _post_register_dwell_seconds()
    if seconds <= 0:
        return
    logger.info("[%s] Staying randomly for %.1fs after successful registration before closing the connection:%s", _log_provider_label(), seconds, email)
    end = time.time() + seconds
    last_touch = 0.0
    while time.time() < end:
        try:
            _check_manual_stop()
        except Exception:
            break
        if time.time() - last_touch >= random.uniform(4.0, 8.0):
            try:
                page = _pick_live_page(context, page) or page
                if page is not None:
                    page.evaluate("() => { try { window.scrollBy(0, Math.floor(Math.random()*80)-40); } catch(e) {} return location.href; }")
            except Exception:
                pass
            last_touch = time.time()
        time.sleep(random.uniform(0.8, 1.8))


def _page_url(page) -> str:
    try:
        return str(page.url or "")
    except Exception:
        return ""


def _visible_locator(page, selectors: list[str], timeout_ms: int = 1500):
    for selector in selectors:
        loc = page.locator(selector).first
        try:
            if loc.is_visible(timeout=timeout_ms):
                return loc
        except Exception:
            continue
    return None


def _visible_textbox_locator(page, timeout_ms: int = 1500):
    """More lenient locating of visible input boxes: compatible with textbox / contenteditable / ordinary input/textarea."""
    candidates = [
        "input:not([type='hidden'])",
        "textarea",
        "[contenteditable='true']",
        "[role='textbox']",
        "[role='combobox'] input",
        "[role='searchbox']",
    ]
    for selector in candidates:
        loc = page.locator(selector).filter(has_not=page.locator("[type='password']")).first if selector.startswith("input") else page.locator(selector).first
        try:
            if loc.is_visible(timeout=timeout_ms):
                return loc
        except Exception:
            continue
    return None


def _fill_first(
    page,
    selectors: list[str],
    value: str,
    timeout_ms: int | None = None,
    typing_delay_range: tuple[int, int] | None = None,
    per_char: bool = False,
) -> bool:
    end = time.time() + ((timeout_ms or _timeout_ms()) / 1000)
    last_err = None
    while time.time() < end:
        loc = _visible_locator(page, selectors, timeout_ms=800)
        if loc is not None:
            try:
                _human_fill_locator(
                    page,
                    loc,
                    value,
                    timeout=5000,
                    typing_delay_range=typing_delay_range,
                    per_char=per_char,
                )
                return True
            except Exception as exc:
                last_err = exc
        time.sleep(0.15 if _fast_mode() else 0.3)
    if last_err:
        logger.debug("[BrowserUse] fill failed: %s", last_err)
    return False


def _click_first(page, selectors: list[str], timeout_ms: int | None = None) -> bool:
    end = time.time() + ((timeout_ms or _timeout_ms()) / 1000)
    while time.time() < end:
        loc = _visible_locator(page, selectors, timeout_ms=800)
        if loc is not None:
            try:
                _human_click_locator(loc, timeout=3000)
                return True
            except Exception:
                pass
        time.sleep(0.15 if _fast_mode() else 0.3)
    return False


def _maybe_accept_cookies(page) -> None:
    _click_first(
        page,
        [
            "button:has-text('Accept')",
            "button:has-text('Accept all')",
            "button:has-text('同意')",
            "button:has-text('接受')",
            "button:has-text('I agree')",
        ],
        timeout_ms=2500,
    )


def _maybe_dismiss_chatgpt_onboarding(page) -> None:
    """Fallback click on the ChatGPT welcome/intro popup after login, so Skyvern does not stay on the popup layer."""
    selectors = [
        "button:has-text('Get started')",
        "button:has-text('Start using ChatGPT')",
        "button:has-text('Continue')",
        "button:has-text('Next')",
        "button:has-text('Done')",
        "button:has-text('Skip')",
        "button:has-text('Maybe later')",
        "button:has-text('开始使用')",
        "button:has-text('继续')",
        "button:has-text('下一步')",
        "button:has-text('完成')",
        "button:has-text('跳过')",
        "[data-testid*='dismiss' i]",
        "[aria-label*='close' i]",
        "[aria-label*='关闭' i]",
    ]
    end = time.time() + (4 if _fast_mode() else 7)
    clicks = 0
    while time.time() < end and clicks < 4:
        if "chatgpt.com" not in _page_url(page).lower():
            return
        if not _click_first(page, selectors, timeout_ms=900):
            return
        clicks += 1
        _human_pause(0.25, 0.6)


def _assert_not_external_idp(page, stage: str) -> None:
    url = _page_url(page).lower()
    bad_hosts = (
        "accounts.google.com",
        "appleid.apple.com",
        "login.microsoftonline.com",
        "github.com/login",
        "facebook.com/login",
    )
    if any(h in url for h in bad_hosts):
        raise RuntimeError(f"[BrowserUse] {stage} entered third-party login by mistake:{url}")


def _quick_auth_state(page) -> dict:
    """Determine the current auth page state with one JS query, to avoid several locators waiting one by one and stalling for tens of seconds."""
    try:
        return page.evaluate(
            """() => {
              const url = String(location.href || '').toLowerCase();
              const visible = (el) => {
                if (!el) return false;
                const st = window.getComputedStyle(el);
                const r = el.getBoundingClientRect();
                return st && st.visibility !== 'hidden' && st.display !== 'none' && r.width > 0 && r.height > 0;
              };
              const q = (s) => !!document.querySelector(s);
              const qv = (s) => Array.from(document.querySelectorAll(s)).some(visible);
              const text = (document.body && document.body.innerText || '').toLowerCase();
              const hasOtp =
                url.includes('email-verification') ||
                url.includes('email_otp') ||
                (url.includes('verify') && url.includes('email')) ||
                qv("input[name='code']") ||
                qv("input[name='otp']") ||
                qv("input[autocomplete='one-time-code']") ||
                qv("input[inputmode='numeric']") ||
                qv("input[type='tel']") ||
                qv("input[maxlength='1']") ||
                qv("input[data-index]") ||
                qv("input[aria-label*='code' i]") ||
                qv("input[aria-label*='digit' i]") ||
                qv("input[placeholder*='code' i]") ||
                (
                  (text.includes('code') || text.includes('verification') || text.includes('verify') ||
                   text.includes('認証コード') || text.includes('確認コード') || text.includes('コード') ||
                   text.includes('验证码') || text.includes('驗證碼')) &&
                  qv("input")
                );
              const hasPassword =
                url.includes('/create-account/password') ||
                url.includes('/u/signup/password') ||
                url.includes('/signup/password') ||
                qv("input[type='password']") ||
                qv("input[name='password']") ||
                qv("input[autocomplete='new-password']");
              let state = 'other';
              // /log-in/password indicates the email has taken the login password branch; even if code/otp wording exists in the page DOM,
              // the registration flow also treats it as an unusable email and must not mistake it for the email verification code page.
              if (url.includes('/log-in/password')) state = 'login_password';
              else if (hasOtp) state = 'email_verification';
              else if (hasPassword) state = 'password';
              else if (url.includes('about-you') || url.includes('profile') || url.includes('create-account/about')) state = 'profile';
              else if (url.includes('chatgpt.com') && !url.includes('/auth/')) state = 'chatgpt';
              return {state, url, hasOtp, hasPassword, textPreview: text.slice(0, 160)};
            }"""
        ) or {"state": "other", "url": _page_url(page)}
    except Exception as exc:
        if _is_target_closed_error(exc):
            raise
        return {"state": "other", "url": _page_url(page), "error": f"{type(exc).__name__}: {exc}"}


def _email_entry_state_pw(page) -> dict:
    """Playwright Roxy-style email entry diagnosis: collect only technical attributes, not depending on page wording."""
    try:
        return page.evaluate(r"""
        () => {
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled;
          const attrText = el => [
            el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
            el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
            el.getAttribute('data-auth-provider'), el.getAttribute('href'), el.getAttribute('action'),
            el.getAttribute('formaction'), el.getAttribute('value'), el.getAttribute('aria-label'), el.className
          ].filter(Boolean).join(' ').toLowerCase();
          const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
            type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
            autocomplete: el.getAttribute('autocomplete') || '', value: el.value || '', placeholder: el.getAttribute('placeholder') || '', aria: el.getAttribute('aria-label') || ''
          })).slice(0, 30);
          const actions = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')]
            .filter(visible).map(el => ({tag: el.tagName, type: el.getAttribute('type') || '', attrs: attrText(el).slice(0, 220)})).slice(0, 50);
          return {url: location.href, title: document.title, inputs, actions};
        }
        """) or {}
    except Exception as exc:
        return {"url": _page_url(page), "error": f"{type(exc).__name__}: {exc}"}


def _is_oauth_consent_like_pw(page) -> bool:
    try:
        return bool(page.evaluate(r"""
        () => {
          const url = String(location.href || '').toLowerCase();
          if (/oauth|authorize|consent/.test(url) && !/login|signup|identifier|email-verification/.test(url)) return true;
          const formsWithEmail = [...document.querySelectorAll('form')]
            .some(form => form.querySelector('input[type="email"],input[name="email"],input[name="username"],input[autocomplete="email"]'));
          if (formsWithEmail) return false;
          const actions = [...document.querySelectorAll('button,a,[role="button"],input[type="submit"],input[type="button"]')]
            .map(el => [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
              el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('href'),
              el.getAttribute('formaction'), el.value, el.className].filter(Boolean).join(' ').toLowerCase())
            .join(' ');
          return /oauth|authorize|consent|grant|allow/.test(actions) && !/email|username/.test(actions);
        }
        """))
    except Exception:
        return False


def _click_email_entry_option_pw(page) -> bool:
    """Roxy Same as above: click the email entry by DOM technical attributes, excluding third-party logins, not depending on visible text."""
    if _is_oauth_consent_like_pw(page):
        logger.info("[BrowserUse] The current page looks like an OAuth authorization page, skipping the email entry fallback click")
        return False
    try:
        result = page.evaluate(r"""
        () => {
          const nodes = [...document.querySelectorAll('button,a,[role="button"],input[type="button"],input[type="submit"]')];
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
          const attrText = el => {
            const own = [
              el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
              el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
              el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'), el.getAttribute('href'), el.getAttribute('action'),
              el.getAttribute('formaction'), el.getAttribute('value'), el.getAttribute('aria-label'), el.className
            ].filter(Boolean).join(' ');
            const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
              .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
                x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
                .filter(Boolean).join(' ')).join(' ');
            return `${own} ${desc}`.toLowerCase();
          };
          const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
          const good = /(^|[^a-z])(email|mail|username|passwordless|otp|magic)([^a-z]|$)/;
          const candidates = nodes
            .map((el, idx) => ({el, idx, attrs: attrText(el), hasLogo: !!el.querySelector('img,svg,use')}))
            .filter(x => visible(x.el) && good.test(x.attrs) && !bad.test(x.attrs) && !x.hasLogo);
          if (candidates.length !== 1) return {ok:false, reason:candidates.length ? 'ambiguous' : 'missing', count:candidates.length, candidates:candidates.slice(0,5).map(x => ({idx:x.idx, attrs:x.attrs.slice(0,180)}))};
          candidates[0].el.scrollIntoView({block:'center', inline:'center'});
          return {ok:true, idx:candidates[0].idx, attrs:candidates[0].attrs.slice(0,180)};
        }
        """) or {}
        if not isinstance(result, dict) or not result.get("ok"):
            logger.info("[BrowserUse] Email entry DOM fallback did not match:%s", result)
            return False
        loc = page.locator('button,a,[role="button"],input[type="button"],input[type="submit"]').nth(int(result.get("idx") or 0))
        _human_click_locator(loc, timeout=3000)
        logger.info("[BrowserUse] Clicked the email entry by DOM attributes:%s", result)
        return True
    except Exception as exc:
        logger.info("[BrowserUse] Email entry DOM fallback click failed:%s: %s", type(exc).__name__, str(exc)[:180])
        return False


def _find_email_input_locator_pw(page, timeout_ms: int = 1000):
    """Roxy Same email input selectors: strict email/username first, then the lenient textbox."""
    strict = [
        "input[type='email']",
        "input[name='email']",
        "input[name='username']",
        "input#email-input",
        "input[autocomplete='email']",
        "input[autocomplete*='email' i]",
        "input[autocomplete='username']",
        "input[id*='email' i]",
        "input[id*='username' i]",
        "input[aria-label*='email' i]",
        "input[placeholder*='email' i]",
        "input[aria-label*='メール']",
        "input[placeholder*='メール']",
        "input[aria-label*='邮箱']",
        "input[placeholder*='邮箱']",
        "input[placeholder*='電子郵件']",
    ]
    loc = _visible_locator(page, strict, timeout_ms=timeout_ms)
    if loc is not None:
        return loc
    return _visible_textbox_locator(page, timeout_ms=timeout_ms)


def _submit_email_step_pw(page, email: str) -> bool:
    """Playwright Roxy-style safe submit: only submit non-third-party buttons near the form that contains the email input."""
    try:
        result = page.evaluate(r"""
        (email) => {
          email = String(email || '').trim().toLowerCase();
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
          const editable = el => visible(el) && !el.readOnly;
          const inputs = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"],input[autocomplete="username"],input#email-input')]
            .filter(editable);
          const input = inputs.find(el => String(el.value || '').trim().toLowerCase() === email) || inputs.find(el => String(el.value || '').includes('@')) || inputs[0];
          if (!input) return {ok:false, reason:'missing_email_input'};
          const value = String(input.value || '').trim();
          if (!value || !value.includes('@')) return {ok:false, reason:'email_value_not_ready', value};
          const form = input.closest('form');
          if (!form) return {ok:false, reason:'missing_form', value};

          const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
          const attrText = el => {
            const own = [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
              el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'),
              el.getAttribute('aria-label'), el.getAttribute('href'), el.getAttribute('formaction'), el.value, el.className]
              .filter(Boolean).join(' ');
            const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
              .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
                x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
                .filter(Boolean).join(' ')).join(' ');
            return `${own} ${desc}`.toLowerCase();
          };
          const formId = form.getAttribute('id') || '';
          const scoped = [
            ...form.querySelectorAll('button,input[type="submit"]'),
            ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])
          ].filter((el, idx, arr) => arr.indexOf(el) === idx);
          const inputRect = input.getBoundingClientRect();
          const candidates = scoped
            .map(el => {
              const r = el.getBoundingClientRect();
              const attrs = attrText(el);
              const hasLogo = !!el.querySelector('img,svg,use');
              const type = String(el.getAttribute('type') || '').toLowerCase();
              const cls = String(el.className || '').toLowerCase();
              const belowInput = r.top >= inputRect.bottom - 12;
              const distance = Math.max(0, r.top - inputRect.bottom) + Math.abs((r.left + r.right) / 2 - (inputRect.left + inputRect.right) / 2) / 10;
              const primary = (el.tagName === 'BUTTON' || el.tagName === 'INPUT') && type === 'submit'
                && (/\bbtn-primary\b/.test(cls) || /\b_primary_/.test(cls) || /\bw-full\b/.test(cls));
              const score = (primary ? 1000 : 0) + (type === 'submit' ? 120 : 0) - distance;
              return {el, attrs, hasLogo, bad: bad.test(attrs), belowInput, distance, primary, score, type};
            })
            .filter(x => visible(x.el) && !x.bad && !x.hasLogo && x.belowInput)
            .sort((a,b) => b.score - a.score || a.distance - b.distance);
          input.scrollIntoView({block:'center', inline:'nearest'});
          input.focus();
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (setter) setter.call(input, value); else input.value = value;
          try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true, inputType:'insertText', data:value})); } catch (_) {}
          try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:value})); } catch (_) {
            input.dispatchEvent(new Event('input', {bubbles:true}));
          }
          input.dispatchEvent(new Event('change', {bubbles:true}));
          input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
          input.blur();
          const submit = candidates[0] ? candidates[0].el : null;
          if (submit) {
            submit.scrollIntoView({block:'center', inline:'center'});
            try {
              submit.dispatchEvent(new MouseEvent('pointerdown', {bubbles:true, cancelable:true, view:window}));
              submit.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
              submit.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
              submit.click();
            } catch (_) {
              if (form && typeof form.requestSubmit === 'function') form.requestSubmit(submit);
              else if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
              else form.submit();
            }
            return {ok:true, value, reason:submit.tagName === 'BUTTON' ? 'button_click' : 'submit_click', attrs:candidates[0].attrs.slice(0,180)};
          }
          if (form && typeof form.requestSubmit === 'function') {
            form.requestSubmit();
            return {ok:true, value, reason:'form_requestSubmit', attrs:''};
          }
          form.submit();
          return {ok:true, value, reason:'form_submit', attrs:''};
        }
        """, email) or {}
        if isinstance(result, dict) and result.get("ok"):
            logger.info("[BrowserUse] Email form safe submit:%s", result)
            _human_pause(0.8, 1.4)
            _assert_not_external_idp(page, "after submitting the email")
            return True
        logger.warning("[BrowserUse] Email safe submit did not match, falling back to Enter:%s", result)
    except Exception as exc:
        logger.warning("[BrowserUse] Email safe submit error, falling back to Enter:%s: %s", type(exc).__name__, str(exc)[:180])
    try:
        _human_pause(0.25, 0.65)
        page.keyboard.press("Enter")
        _human_pause(0.8, 1.4)
        _assert_not_external_idp(page, "Enter after submitting the email")
        return True
    except Exception:
        return False


def _wait_for_email_input_pw(page, timeout_ms: int | None = None):
    """Enter the email login/registration method and return the visible email input box that was found."""
    fill_timeout_ms = timeout_ms if timeout_ms is not None else min(_timeout_ms(), 24000)
    end = time.time() + (fill_timeout_ms / 1000.0)
    clicked_email_option = False
    last_state: dict[str, Any] | None = None

    while time.time() < end:
        loc = _find_email_input_locator_pw(page, timeout_ms=1000)
        if loc is not None:
            return loc

        last_state = _email_entry_state_pw(page)
        if not clicked_email_option:
            # Try the original multilingual explicit selectors first, then fall back to the Roxy DOM attributes.
            clicked_email_option = _click_first(
                page,
                [
                    "button[data-testid*='email' i]",
                    "button[data-provider='email']",
                    "button[data-auth-provider='email']",
                    "button[data-testid*='mail' i]",
                    "button:has-text('Continue with email')",
                    "button:has-text('Sign up with email')",
                    "button:has-text('Log in with email')",
                    "button:has-text('Email')",
                    "button:has-text('メールで続行')",
                    "button:has-text('メールアドレスで続行')",
                    "button:has-text('メール')",
                    "button:has-text('使用邮箱')",
                    "button:has-text('使用電子郵件')",
                    "button:has-text('邮箱')",
                    "button:has-text('電子郵件')",
                    "a:has-text('Continue with email')",
                    "a:has-text('メールで続行')",
                ],
                timeout_ms=2500,
            ) or _click_email_entry_option_pw(page)
            if clicked_email_option:
                _human_pause(0.8, 1.6)
                _assert_not_external_idp(page, "after clicking the email entry")
                continue

        time.sleep(0.35 if _fast_mode() else 0.55)

    raise RuntimeError(f"Cannot find the email input box / email entry, page={_page_url(page) or '-'} state={last_state}")


def _type_email(page, email: str, timeout_ms: int | None = None) -> None:
    """After the email input box is found, type the email character by character like a human and submit it."""
    loc = _wait_for_email_input_pw(page, timeout_ms=timeout_ms)
    _human_fill_locator(
        page,
        loc,
        email,
        timeout=6000,
        typing_delay_range=_cloud_typing_delay("email"),
        per_char=True,
    )
    _human_pause(0.3, 0.8)
    if not _submit_email_step_pw(page, email):
        raise RuntimeError(f"Email entered but submission failed, page={_page_url(page) or '-'} state={_email_entry_state_pw(page)}")


def _wait_after_email_submit_transition(page, context=None, timeout: int = 14) -> str:
    """After submitting the email, confirm the page really left the email input page, to avoid waiting idly for the OTP."""
    end = time.time() + timeout
    last_state = "other"
    last_url = ""
    while time.time() < end:
        _check_manual_stop()
        try:
            page = _browser_use_heartbeat(page, context=context, label="email-submit-transition")
        except Exception as exc:
            if _is_target_closed_error(exc):
                raise
        info = _quick_auth_state(page)
        state = str(info.get("state") or "other")
        url = str(info.get("url") or _page_url(page) or "")
        last_state, last_url = state, url
        lower = url.lower()
        if "/log-in/password" in lower:
            return "login_password"
        if any(x in lower for x in ("/create-account/password", "/u/signup/password", "/signup/password")):
            return "password"
        if state in ("email_verification", "password", "login_password", "profile", "chatgpt"):
            return state
        if any(x in lower for x in ("email-verification", "/password", "about-you", "profile")):
            return state
        if "chatgpt.com" in lower and "/auth/" not in lower:
            return "chatgpt"
        time.sleep(0.25 if _fast_mode() else 0.5)
    if "chatgpt.com/auth/login" in last_url.lower():
        return "email_page"
    return last_state


def _submit_email_until_transition(
    page,
    context,
    email: str | None,
    *,
    attempts: int = 2,
    timeout_ms: int | None = None,
    email_supplier: Callable[[], str] | None = None,
) -> str:
    """
    Fill in and submit the email, and confirm entering the password/OTP/following page.
    If still on chatgpt.com/auth/login?email=..., retry once, to avoid waiting for the email verification code uselessly.
    """
    last_state = "other"
    current_email = str(email or "").strip()
    for attempt in range(1, max(1, attempts) + 1):
        _check_manual_stop()
        logger.info("[BrowserUse] Submit email attempt %s/%s:%s", attempt, attempts, current_email or "Allocated once the input box is found on the page")
        if current_email:
            _type_email(page, current_email, timeout_ms=timeout_ms)
        else:
            # First confirm the page has a usable input box, then claim the email; the claim must not happen before the page navigation.
            email_input = _wait_for_email_input_pw(page, timeout_ms=timeout_ms)
            if email_supplier is None:
                raise RuntimeError("An email input box was found, but no email allocator was provided")
            current_email = str(email_supplier() or "").strip()
            if not current_email:
                raise RuntimeError("The email allocator returned an empty email address")
            _human_fill_locator(
                page,
                email_input,
                current_email,
                timeout=6000,
                typing_delay_range=_cloud_typing_delay("email"),
                per_char=True,
            )
            _human_pause(0.3, 0.8)
            if not _submit_email_step_pw(page, current_email):
                raise RuntimeError(f"Email entered but submission failed, page={_page_url(page) or '-'} state={_email_entry_state_pw(page)}")
        _check_manual_stop()
        last_state = _wait_after_email_submit_transition(page, context=context, timeout=10 if _fast_mode() else 16)
        logger.info("[BrowserUse] State after the email was submitted:%s url=%s", last_state, _page_url(page) or "-")
        if last_state == "login_password":
            raise RuntimeError(f"After submitting the email it entered the login password page; treated as a registered/unusable email and deactivated: url={_page_url(page) or 'https://auth.openai.com/log-in/password'}")
        if last_state != "email_page":
            return last_state
        if attempt < attempts:
            logger.warning("[BrowserUse] After submitting the email it still stays on the login page, preparing to retry the submit:%s", _page_url(page) or "-")
    raise RuntimeError(f"After submitting the email it still stays on the login page and the password/verification code page was not triggered:state={last_state} url={_page_url(page) or '-'}")


def _is_password_page(page) -> bool:
    try:
        return _quick_auth_state(page).get("state") == "password"
    except Exception:
        raise
    url = _page_url(page).lower()
    if any(x in url for x in ("/create-account/password", "/u/signup/password", "/signup/password")):
        return True
    if "/log-in/password" in url:
        return False
    loc = _visible_locator(
        page,
        [
            "input[type='password']",
            "input[name='password']",
            "input[autocomplete='new-password']",
        ],
        timeout_ms=500,
    )
    return loc is not None and "email-verification" not in url


def _is_signup_password_page(page) -> bool:
    """Recognize the registration password page more reliably: look at the URL first, then at the password input box."""
    try:
        url = str(_page_url(page) or "").lower()
    except Exception:
        url = ""
    if any(x in url for x in ("/create-account/password", "/u/signup/password", "/signup/password")):
        return True
    if "/log-in/password" in url:
        return False
    try:
        state = _quick_auth_state(page)
        if str(state.get("state") or "") == "password":
            return True
    except Exception:
        pass
    try:
        loc = _visible_locator(
            page,
            [
                "input[type='password']",
                "input[name='password']",
                "input[autocomplete='new-password']",
            ],
            timeout_ms=500,
        )
        return loc is not None and "email-verification" not in url
    except Exception:
        return False


def _is_email_verification_page(page) -> bool:
    try:
        if "/log-in/password" in (_page_url(page) or "").lower():
            return False
        return _quick_auth_state(page).get("state") == "email_verification"
    except Exception:
        raise
    url = _page_url(page).lower()
    if "email-verification" in url or "email_otp" in url or "verify" in url and "email" in url:
        return True
    loc = _visible_locator(
        page,
        [
            "input[name='code']",
            "input[autocomplete='one-time-code']",
            "input[inputmode='numeric']",
            "input[aria-label*='code' i]",
            "input[placeholder*='code' i]",
        ],
        timeout_ms=500,
    )
    return loc is not None


def _click_passwordless_signup_if_present(page) -> bool:
    """On the registration/login password page, prefer clicking 'use a one-time code' to enter the email OTP flow."""
    selectors = [
        "button[name='intent'][value='passwordless_signup_send_otp']",
        "input[type='submit'][name='intent'][value='passwordless_signup_send_otp']",
        "button[name='intent'][value='passwordless_login_send_otp']",
        "input[type='submit'][name='intent'][value='passwordless_login_send_otp']",
        "button[name='intent'][value*='passwordless'][value*='otp']",
        "input[type='submit'][name='intent'][value*='passwordless'][value*='otp']",
        "button[name='intent'][value*='passwordless'][value*='send_otp']",
        "input[type='submit'][name='intent'][value*='passwordless'][value*='send_otp']",
        "button:has-text('使用一次性验证码注册')",
        "button:has-text('使用一次性验证码登录')",
        "button:has-text('使用一次性验证码')",
        "button:has-text('使用一次性驗證碼註冊')",
        "button:has-text('使用一次性驗證碼登入')",
        "button:has-text('Use a one-time code')",
        "button:has-text('one-time code')",
        "button:has-text('Continue with a one-time code')",
        "button:has-text('Log in with a one-time code')",
        "button:has-text('Sign up with a one-time code')",
        "button:has-text('ワンタイムコード')",
        "button:has-text('認証コード')",
        "a:has-text('使用一次性验证码')",
        "a:has-text('使用一次性驗證碼')",
        "a:has-text('Use a one-time code')",
        "a:has-text('one-time code')",
        "a:has-text('ワンタイムコード')",
        "a:has-text('認証コード')",
        "[role='button']:has-text('使用一次性验证码注册')",
        "[role='button']:has-text('使用一次性验证码登录')",
        "[role='button']:has-text('Continue with a one-time code')",
        "[role='button']:has-text('one-time code')",
    ]
    if _click_first(page, selectors, timeout_ms=1500):
        return True
    try:
        return bool(page.evaluate(
            """() => {
              const visible = el => {
                if (!el) return false;
                const st = getComputedStyle(el);
                const r = el.getBoundingClientRect();
                return st.visibility !== 'hidden' && st.display !== 'none' && r.width > 0 && r.height > 0;
              };
              const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
              const norm = s => String(s || '').replace(/\\s+/g, '').toLowerCase();
              const btn = [...document.querySelectorAll('button,a,input[type="submit"],[role="button"],[role="link"]')]
                .filter(el => visible(el) && enabled(el))
                .find(el => {
                  const name = String(el.getAttribute('name') || '').toLowerCase();
                  const value = String(el.getAttribute('value') || '').toLowerCase();
                  const attrs = [
                    el.id, name, value, el.getAttribute('aria-label'), el.getAttribute('title'),
                    el.getAttribute('data-testid'), el.getAttribute('data-dd-action-name'), el.className, el.textContent
                  ].join(' ').toLowerCase();
                  const text = norm(el.textContent || el.getAttribute('value') || '');
                  return (name === 'intent' && value.includes('passwordless') && value.includes('send_otp'))
                    || (name === 'intent' && value.includes('passwordless') && value.includes('otp'))
                    || (name === 'intent' && value === 'passwordless_signup_send_otp')
                    || (name === 'intent' && value === 'passwordless_login_send_otp')
                    || /passwordless.*otp|otp.*passwordless|one[-_\\s]?time.*code|code.*one[-_\\s]?time/.test(attrs)
                    || text.includes('使用一次性验证码注册')
                    || text.includes('使用一次性验证码登录')
                    || text.includes('使用一次性验证码')
                    || text.includes('使用一次性驗證碼註冊')
                    || text.includes('使用一次性驗證碼登入')
                    || text.includes('一次性验证码')
                    || text.includes('一次性驗證碼')
                    || text.includes('ワンタイムコード')
                    || text.includes('認証コード')
                    || text.includes('continuewithaone-timecode')
                    || text.includes('loginwithaone-timecode')
                    || text.includes('signupwithaone-timecode')
                    || text.includes('one-timecode');
                });
              if (!btn) return false;
              btn.scrollIntoView({block:'center'});
              try {
                btn.dispatchEvent(new MouseEvent('pointerdown', {bubbles:true, cancelable:true, view:window}));
                btn.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
                btn.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
                btn.click();
              } catch (e) {
                const form = btn.closest('form');
                if (form && typeof form.requestSubmit === 'function') form.requestSubmit(btn);
                else if (form) form.submit();
                else throw e;
              }
              return true;
            }"""
        ))
    except Exception:
        return False


def _click_continue_with_password_if_present(page) -> bool:
    """On the email verification code page click 'continue with password' to switch to /create-account/password and create a password account."""
    selectors = [
        "a[href*='/create-account/password']",
        "a[href='/create-account/password']",
        "[data-login-web-auth-control='true'][href*='/create-account/password']",
        "[role='link'][href*='/create-account/password']",
        "[role='button'][href*='/create-account/password']",
    ]
    if _click_first(page, selectors, timeout_ms=1800):
        return True
    try:
        return bool(page.evaluate(
            """() => {
              const visible = el => {
                if (!el) return false;
                const st = getComputedStyle(el);
                const r = el.getBoundingClientRect();
                return st.visibility !== 'hidden' && st.display !== 'none' && r.width > 0 && r.height > 0;
              };
              const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
              const btn = [...document.querySelectorAll('a,button,[role="link"],[role="button"]')]
                .filter(el => visible(el) && enabled(el))
                .find(el => {
                  const href = String(el.getAttribute('href') || '').toLowerCase();
                  const attrs = [
                    href, el.id, el.getAttribute('aria-label'), el.getAttribute('title'),
                    el.getAttribute('data-testid'), el.getAttribute('data-login-web-auth-control'),
                    el.getAttribute('data-dd-action-name'), el.className
                  ].join(' ').toLowerCase();
                  return href.includes('/create-account/password')
                    || attrs.includes('/create-account/password');
                });
              if (!btn) return false;
              btn.scrollIntoView({block:'center'});
              try {
                btn.dispatchEvent(new MouseEvent('pointerdown', {bubbles:true, cancelable:true, view:window}));
                btn.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
                btn.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
                btn.click();
              } catch (e) {
                const href = btn.getAttribute('href');
                if (href) window.location.href = href;
                else throw e;
              }
              return true;
            }"""
        ))
    except Exception:
        return False


def _fill_password_if_present(page, email: str, timeout: int = 25, context=None) -> str | None:
    started = time.time()
    end = time.time() + timeout
    last_heartbeat = 0.0
    last_log = 0.0
    while time.time() < end:
        # If already on the verification code page after submitting the email, prefer clicking "continue with password" to switch to the password creation page.
        try:
            if not _is_signup_password_page(page):
                quick = _quick_auth_state(page)
                if str(quick.get("state") or "") == "email_verification":
                    if _click_continue_with_password_if_present(page):
                        logger.info("[BrowserUse] Clicked 'continue with password' on the email verification code page:url=%s", quick.get("url") or _page_url(page) or "-")
                        time.sleep(0.4 if _fast_mode() else 1.0)
                        continue
                    logger.info("[BrowserUse] Already on the email verification code page, but the 'continue with password' button was not found, continuing to wait for the password page:url=%s", quick.get("url") or _page_url(page) or "-")
        except Exception:
            pass
        if time.time() - last_heartbeat > 3:
            try:
                page = _browser_use_heartbeat(page, context=context, label="password-detect")
            except Exception as exc:
                if _is_target_closed_error(exc):
                    raise
                if _is_transient_navigation_error(exc):
                    logger.info("[BrowserUse] Password page detection hit a page navigation, retrying shortly:%s", str(exc)[:140])
                    time.sleep(0.4 if _fast_mode() else 1.0)
                    continue
                raise
            last_heartbeat = time.time()
        state_info = _quick_auth_state(page)
        state = "password" if _is_signup_password_page(page) else str(state_info.get("state") or "other")
        if time.time() - last_log > 3:
            logger.info("[BrowserUse] Detecting the password/verification code page:state=%s url=%s", state, state_info.get("url") or "-")
            last_log = time.time()
        if state == "email_verification" and not _is_signup_password_page(page):
            if _click_continue_with_password_if_present(page):
                logger.info("[BrowserUse] Clicked 'continue with password' on the email verification code page:email=%s", email)
                time.sleep(0.4 if _fast_mode() else 1.0)
                continue
            try:
                logger.info("[BrowserUse] No button matched on the email verification code page, falling back to jumping directly to the password page:email=%s", email)
                page.goto("https://auth.openai.com/create-account/password", wait_until="domcontentloaded", timeout=_timeout_ms(getattr(_cfg, "BROWSER_USE_NAVIGATION_TIMEOUT", 90)))
                time.sleep(0.6 if _fast_mode() else 1.2)
                continue
            except Exception as exc:
                logger.info("[BrowserUse] Fallback jump from the email verification code page to the password page failed:%s", str(exc)[:180])
                # Do not exit directly, keep waiting for the page to switch to the password page by itself
                time.sleep(0.8 if _fast_mode() else 1.5)
                continue
        if state not in ("password", "login_password"):
            # If /auth/login is still shown after submitting the email but the page has actually rendered the verification code input box,
            # the DOM state on some Browser Use targets can lag briefly. Do not wait long in the "password page detection";
            # hand it directly to the later OTP stage, so the cloud session is not dragged until it is closed.
            # fast mode must not give up after 3 seconds either: after submitting the email it often still stays on /auth/login,
            # and one has to wait for the jump to auth.openai.com or for password/OTP controls to appear.
            if _fast_mode() and time.time() - started >= 8:
                logger.info("[BrowserUse] Password page not detected, entering the OTP stage early:state=%s url=%s", state, state_info.get("url") or "-")
                return None
            time.sleep(0.15 if _fast_mode() else 0.4)
            continue
        if state == "login_password" and _click_passwordless_signup_if_present(page):
            logger.info("[BrowserUse] Password page detected, clicked the one-time code entry:state=%s email=%s", state, email)
            wait_end = time.time() + 20
            while time.time() < wait_end:
                state_after = _quick_auth_state(page)
                if state_after.get("state") == "email_verification":
                    logger.info("[BrowserUse] Entered the email verification code page through the one-time code entry")
                    return None
                if state_after.get("state") == "chatgpt":
                    logger.info("[BrowserUse] Entered after the one-time code entry ChatGPT")
                    return None
                if state_after.get("state") not in ("password", "login_password"):
                    return None
                time.sleep(0.2 if _fast_mode() else 0.5)
            logger.info("[BrowserUse] Clicked the one-time code entry, the OTP page was not detected immediately, leaving it to the following OTP stage")
            return None
        if state == "login_password":
            logger.info("[BrowserUse] This is the login password page but no one-time code entry was found, skipping the password fill and leaving it to the OTP stage:url=%s", state_info.get("url") or "-")
            return None
        password = _registration_password()
        logger.info("[BrowserUse] Password page detected, setting the password (%s characters):%s", len(password), email)
        submit_result = page.evaluate(
            r"""(password) => {
              const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                && getComputedStyle(el).visibility !== 'hidden'
                && getComputedStyle(el).display !== 'none'
                && !el.disabled && !el.readOnly;
              const enabled = el => !!el && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
              const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
              const inputs = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
                .filter(visible);
              const input = inputs[0];
              if (!input) return {ok:false, reason:'missing_password_input', url: location.href};
              const form = input.closest('form');
              const scope = form || document;
              const buttons = [...scope.querySelectorAll('button,input[type="submit"],[role="button"]')]
                .filter(el => visible(el) && enabled(el))
                .map((el, idx) => {
                  const r = el.getBoundingClientRect();
                  const ir = input.getBoundingClientRect();
                  const attrs = [
                    el.getAttribute('type'), el.getAttribute('data-dd-action-name'),
                    el.getAttribute('data-login-web-auth-control'), el.getAttribute('aria-label'),
                    el.getAttribute('name'), el.getAttribute('value'), el.textContent
                  ].join(' ').toLowerCase();
                  const text = norm(el.textContent || el.getAttribute('value') || '');
                  let score = 0;
                  if ((el.getAttribute('type') || '').toLowerCase() === 'submit') score += 80;
                  if ((el.getAttribute('data-dd-action-name') || '').toLowerCase() === 'continue') score += 90;
                  if (String(el.getAttribute('data-login-web-auth-control') || '').toLowerCase() === 'true') score += 70;
                  if (/continue|next|submit|create|続行/.test(attrs) || /continue|next|submit|create|続行/.test(text)) score += 50;
                  if (r.top >= ir.bottom - 10) score += 40;
                  const dist = Math.max(0, r.top - ir.bottom) + Math.abs((r.left + r.right - ir.left - ir.right) / 2) / 10;
                  return {el, idx, score, dist, attrs};
                })
                .sort((a,b) => b.score - a.score || a.dist - b.dist);
              const target = buttons[0] ? buttons[0].el : null;
              const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
              input.scrollIntoView({block:'center', inline:'nearest'});
              input.focus();
              if (setter) setter.call(input, String(password || '')); else input.value = String(password || '');
              try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true, inputType:'insertText', data:String(password || '')})); } catch (_) {}
              try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:String(password || '')})); } catch (_) {
                input.dispatchEvent(new Event('input', {bubbles:true}));
              }
              input.dispatchEvent(new Event('change', {bubbles:true}));
              input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
              input.blur();
              if (!target) {
                if (form && typeof form.requestSubmit === 'function') {
                  form.requestSubmit();
                  return {ok:true, reason:'form_requestSubmit', url: location.href, hasForm: true, buttons: buttons.length};
                }
                if (form) {
                  form.submit();
                  return {ok:true, reason:'form_submit', url: location.href, hasForm: true, buttons: buttons.length};
                }
                return {ok:false, reason:'missing_enabled_submit', url: location.href, hasForm: !!form, buttons: buttons.length};
              }
              target.scrollIntoView({block:'center'});
              try {
                target.dispatchEvent(new MouseEvent('pointerdown', {bubbles:true, cancelable:true, view:window}));
                target.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
                target.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
                target.click();
              } catch (e) {
                if (form && typeof form.requestSubmit === 'function') form.requestSubmit(target);
                else if (form) form.submit();
                else throw e;
              }
              return {ok:true, reason:'button_click', url: location.href, hasForm: !!form, buttons: buttons.length, attrs: (buttons[0]?.attrs || '').slice(0, 180)};
            }""",
            password,
        ) or {}
        if not submit_result.get("ok"):
            raise RuntimeError(f"Cannot find a clickable Continue button on the password page:{submit_result} state={state_info}")
        logger.info("[BrowserUse] Filled in and clicked Continue on the password page:detail=%s", {k: v for k, v in submit_result.items() if k != "button"})
        _bu_delay("form")
        wait_end = time.time() + (8 if _fast_mode() else 14)
        retried_submit = False
        while time.time() < wait_end:
            state_after = _quick_auth_state(page)
            state_name = str(state_after.get("state") or "other")
            if state_name in ("email_verification", "profile", "chatgpt"):
                logger.info("[BrowserUse] After the password page was submitted it entered the following state:state=%s url=%s", state_name, state_after.get("url") or "-")
                return password
            if not retried_submit and state_name == "password" and time.time() > wait_end - (5 if _fast_mode() else 8):
                retried_submit = True
                logger.info("[BrowserUse] The password page did not move on after submit, retrying Continue/Enter once after a wait:url=%s", state_after.get("url") or "-")
                _human_pause(1.2, 2.2)
                if not _click_first(
                    page,
                    [
                        "button[data-dd-action-name='Continue']",
                        "button[data-login-web-auth-control='true'][type='submit']",
                        "button[type='submit']",
                        "form button",
                    ],
                    timeout_ms=4000,
                ):
                    try:
                        page.keyboard.press("Enter")
                    except Exception:
                        pass
            if state_name not in ("password", "login_password"):
                return password
            time.sleep(0.25 if _fast_mode() else 0.5)
        return password
    return None


def _type_otp(page, code: str) -> None:
    code = str(code or "").strip()
    if not code:
        raise RuntimeError("OTP is empty")

    # single box
    if _fill_first(
        page,
        [
            "input[name='code']",
            "input[autocomplete='one-time-code']",
            "input[name='otp']",
            "input[aria-label*='code' i]",
            "input[placeholder*='code' i]",
            "input[inputmode='numeric']",
        ],
        code,
        timeout_ms=5000,
        typing_delay_range=_cloud_typing_delay("otp"),
        per_char=True,
    ):
        return

    # 6 split boxes
    boxes = page.locator("input[maxlength='1'], input[data-index], input[aria-label*='digit' i]")
    try:
        count = boxes.count()
    except Exception:
        count = 0
    if count >= len(code):
        for i, ch in enumerate(code):
            box = boxes.nth(i)
            try:
                _human_click_locator(box, timeout=1200)
                _human_pause(0.05, 0.14)
                page.keyboard.type(ch, delay=random.randint(35, 110))
            except Exception:
                raise
            _human_pause(0.04, 0.16)
        return
    raise RuntimeError("OTP input box not found")


def _clear_otp_inputs(page) -> None:
    try:
        page.evaluate(
            """() => {
              for (const el of document.querySelectorAll('input')) {
                const t = (el.type || '').toLowerCase();
                const n = (el.name || '').toLowerCase();
                const a = (el.autocomplete || '').toLowerCase();
                if (t === 'tel' || t === 'number' || t === 'text' || n.includes('code') || n.includes('otp') || a.includes('one-time')) {
                  const proto = window.HTMLInputElement.prototype;
                  const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
                  if (setter) setter.call(el, ''); else el.value = '';
                  el.dispatchEvent(new Event('input', {bubbles:true}));
                  el.dispatchEvent(new Event('change', {bubbles:true}));
                }
              }
            }"""
        )
    except Exception:
        pass


def _click_continue(page) -> None:
    if not _click_first(
        page,
        [
            "button[type='submit']",
            "button[data-dd-action-name='Continue']",
            "button[data-dd-action-name='continue']",
            "button[data-login-web-auth-control='true'][type='submit']",
            "button:has-text('Continue')",
            "button:has-text('Verify')",
            "button:has-text('Submit')",
            "button:has-text('続行')",
            "button:has-text('继续')",
            "button:has-text('验证')",
            "form button",
        ],
        timeout_ms=5000,
    ):
        _human_pause(0.12, 0.35)
        page.keyboard.press("Enter")


def _click_resend_otp(page) -> bool:
    """Click "resend verification code" on the email verification code page.

    Do not use Playwright has-text / visible wording matching, to avoid instability across languages, translations and OCR/text recognition.
    Strategy: find non-submit buttons/links near the OTP input box in the page DOM, score them by position, type and attribute names, and click.
    """
    try:
        result = page.evaluate(
            r"""
            () => {
              const visible = (el) => {
                if (!el) return false;
                const st = window.getComputedStyle(el);
                const r = el.getBoundingClientRect();
                return st && st.visibility !== 'hidden' && st.display !== 'none' && r.width > 1 && r.height > 1;
              };
              const disabled = (el) => {
                return !!(
                  el.disabled ||
                  el.getAttribute('aria-disabled') === 'true' ||
                  el.closest('[aria-disabled="true"]')
                );
              };
              const attrBlob = (el) => [
                el.id,
                el.name,
                el.className,
                el.getAttribute('data-testid'),
                el.getAttribute('data-test-id'),
                el.getAttribute('data-qa'),
                el.getAttribute('data-action'),
                el.getAttribute('aria-label'),
                el.getAttribute('title'),
                el.getAttribute('href'),
                el.getAttribute('type'),
                el.getAttribute('value'),
              ].filter(Boolean).join(' ').toLowerCase();

              const otpInputs = Array.from(document.querySelectorAll('input, textarea'))
                .filter(visible)
                .filter(el => {
                  const b = attrBlob(el);
                  const maxLen = Number(el.getAttribute('maxlength') || '0');
                  return (
                    el.autocomplete === 'one-time-code' ||
                    el.inputMode === 'numeric' ||
                    /otp|code|verification|verify|token|pin/.test(b) ||
                    maxLen === 1 || maxLen === 6
                  );
                });
              const inputRects = otpInputs.map(el => el.getBoundingClientRect());
              const inputBottom = inputRects.length ? Math.max(...inputRects.map(r => r.bottom)) : 0;
              const inputTop = inputRects.length ? Math.min(...inputRects.map(r => r.top)) : 0;
              const inputLeft = inputRects.length ? Math.min(...inputRects.map(r => r.left)) : 0;
              const inputRight = inputRects.length ? Math.max(...inputRects.map(r => r.right)) : window.innerWidth;

              const candidates = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="button"], input[type="submit"]'))
                .filter(visible)
                .filter(el => !disabled(el));

              let best = null;
              let bestScore = -999;
              const rows = [];
              for (const el of candidates) {
                const r = el.getBoundingClientRect();
                const b = attrBlob(el);
                const tag = el.tagName.toLowerCase();
                const type = String(el.getAttribute('type') || '').toLowerCase();
                const name = String(el.getAttribute('name') || '').toLowerCase();
                const value = String(el.getAttribute('value') || '').toLowerCase();
                let score = 0;

                // Attribute heuristics, without reading the visible innerText and without depending on the page language wording.
                if (name === 'intent' && value === 'resend') score += 80;
                if (/resend|send.?again|again|retry|otp|verification|verify|email.?code|code/.test(b)) score += 20;
                if (/continue|submit|next|primary|login|signup|create|authorize|consent/.test(b)) score -= 8;
                if (tag === 'a') score += 4;
                if (tag === 'button' && type && type !== 'submit') score += 6;
                if (tag === 'button' && type === 'submit' && !(name === 'intent' && value === 'resend')) score -= 10;

                // Position heuristics: the resend entry is usually below or near the OTP input box; the main submit button is usually lower / bigger.
                if (inputRects.length) {
                  if (r.top >= inputTop - 20 && r.top <= inputBottom + 220) score += 8;
                  if (r.top > inputBottom - 10) score += 5;
                  if (r.left >= inputLeft - 160 && r.right <= inputRight + 260) score += 3;
                  const area = r.width * r.height;
                  if (area < 18000) score += 2;       // prefer text-like links / small buttons
                  if (area > 26000) score -= 4;       // down-weight big Continue/Submit buttons
                } else {
                  if (r.top > window.innerHeight * 0.25 && r.top < window.innerHeight * 0.85) score += 2;
                }

                rows.push({tag, type, id: el.id || '', cls: String(el.className || '').slice(0, 80), score, rect: {x:r.x,y:r.y,w:r.width,h:r.height}});
                if (score > bestScore) {
                  bestScore = score;
                  best = el;
                }
              }

              if (!best || bestScore < 4) {
                return {ok:false, reason:'no_candidate', bestScore, candidates: rows.slice(0, 8)};
              }
              best.scrollIntoView({block:'center', inline:'center'});
              best.click();
              return {ok:true, score:bestScore, tag:best.tagName, id:best.id || '', type:best.getAttribute('type') || '', candidates: rows.slice(0, 8)};
            }
            """
        )
        logger.info("[BrowserUse][OTP] Non-text resend button probe result:%s", result)
        return bool(isinstance(result, dict) and result.get("ok"))
    except Exception as exc:
        logger.info("[BrowserUse][OTP] Non-text resend button probe failed:%s: %s", type(exc).__name__, str(exc)[:160])
        return False


def _wait_after_otp(page, timeout: int = 12) -> str:
    """Returns accepted / invalid / unknown."""
    end = time.time() + timeout
    while time.time() < end:
        url = _page_url(page).lower()
        body = ""
        try:
            body = (page.locator("body").inner_text(timeout=1000) or "").lower()
        except Exception:
            pass
        if any(x in url for x in ("about-you", "profile", "chatgpt.com", "create-account/about")):
            return "accepted"
        if any(x in body for x in ("incorrect", "invalid", "expired", "错误", "过期", "无效")) and _is_email_verification_page(page):
            return "invalid"
        if "chatgpt.com" in url and "auth" not in url:
            return "accepted"
        time.sleep(0.25 if _fast_mode() else 0.5)
    return "unknown"


def _fill_birthday_fields(page, birthday: str) -> None:
    # birthday: YYYY-MM-DD
    try:
        year, month, day = [int(x) for x in birthday.split("-")]
    except Exception as exc:
        raise RuntimeError(f"Birthday format should be YYYY-MM-DD: {birthday}") from exc

    # age number page
    age = max(18, min(60, 2026 - year))
    if _fill_first(
        page,
        [
            "input[name='age']",
            "input[id*='age' i]",
            "input[aria-label*='age' i]",
            "input[placeholder*='age' i]",
            "input[type='number']",
        ],
        str(age),
        timeout_ms=2500,
    ):
        return

    # year/month/day select / spinbutton, cover as much as possible
    y, m, d = str(year), str(month), str(day)
    # year/month/day inputs
    for selectors, value in (
        ([
            "select[name*='year' i]",
            "input[name*='year' i]",
            "input[aria-label*='year' i]",
            "[data-type='year'] input",
        ], y),
        ([
            "select[name*='month' i]",
            "input[name*='month' i]",
            "input[aria-label*='month' i]",
            "[data-type='month'] input",
        ], m),
        ([
            "select[name*='day' i]",
            "input[name*='day' i]",
            "input[aria-label*='day' i]",
            "[data-type='day'] input",
        ], d),
    ):
        loc = _visible_locator(page, selectors, timeout_ms=800)
        if loc is None:
            continue
        try:
            tag = (loc.evaluate("el => el.tagName") or "").lower()
            if tag == "select":
                _human_pause(0.12, 0.35)
                try:
                    loc.select_option(value=value)
                except Exception:
                    _human_pause(0.08, 0.2)
                    loc.select_option(label=value)
            else:
                _human_pause(0.08, 0.22)
                _human_fill_locator(page, loc, value, timeout=5000)
        except Exception:
            pass



def _profile_diagnostics(page) -> dict:
    try:
        return page.evaluate(
            r"""
            () => {
              const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
              const inputs = [...document.querySelectorAll('input,textarea,select')].map(el => ({
                tag: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
                placeholder: el.getAttribute('placeholder') || '', aria: el.getAttribute('aria-label') || '',
                value: el.type === 'password' ? '<password>' : (el.value || ''), visible: visible(el), disabled: !!el.disabled,
              })).slice(0, 60);
              const buttons = [...document.querySelectorAll('button,input[type="submit"],[role="button"]')].map(el => ({
                tag: el.tagName, type: el.getAttribute('type') || '', text: (el.innerText || el.textContent || el.value || '').trim().slice(0,80),
                disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true', visible: visible(el),
              })).slice(0, 30);
              return {url: location.href, title: document.title, inputs, buttons, body: (document.body?.innerText || '').slice(0,500)};
            }
            """
        ) or {"url": _page_url(page)}
    except Exception as exc:
        return {"url": _page_url(page), "error": f"{type(exc).__name__}: {exc}"}


def _has_chatgpt_access_token(page) -> bool:
    try:
        if "chatgpt.com" not in _page_url(page).lower():
            return False
        data = page.evaluate(
            """async ({timeoutMs}) => {
              const ctrl = new AbortController();
              const timer = setTimeout(() => ctrl.abort('timeout'), timeoutMs);
              try {
                const r = await fetch('/api/auth/session', {
                  credentials: 'include',
                  cache: 'no-store',
                  headers: {'accept': 'application/json'},
                  signal: ctrl.signal,
                });
                return await r.json();
              } finally {
                clearTimeout(timer);
              }
            }""",
            {"timeoutMs": 2500 if _fast_mode() else 4000},
        )
        return bool(isinstance(data, dict) and data.get("accessToken"))
    except Exception:
        return False


def _fill_spinbutton_birthday(page, birthday: str) -> bool:
    """Playwright Fallback fill of the React Aria spinbutton year/month/day."""
    try:
        y, m, d = birthday.split("-")
    except Exception:
        return False
    ok = False
    for selector, value in [
        ('[role="spinbutton"][data-type="year"]', y),
        ('[role="spinbutton"][data-type="month"]', str(int(m)).zfill(2)),
        ('[role="spinbutton"][data-type="day"]', str(int(d)).zfill(2)),
    ]:
        try:
            loc = page.locator(selector).first
            if loc.count() <= 0:
                continue
            _human_pause(0.08, 0.22)
            _safe_scroll_locator(loc, timeout=1200)
            _human_click_locator(loc, timeout=1800)
            page.keyboard.press("Meta+A")
            _human_pause(0.05, 0.15)
            page.keyboard.type(str(value), delay=random.randint(90, 220) if _fast_mode() else random.randint(120, 320))
            loc.evaluate("el => { el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); el.blur?.(); }")
            ok = True
        except Exception:
            try:
                _human_pause(0.08, 0.22)
                page.keyboard.press("Control+A")
                _human_pause(0.05, 0.15)
                page.keyboard.type(str(value), delay=random.randint(90, 220) if _fast_mode() else random.randint(120, 320))
                ok = True
            except Exception:
                pass
    if ok:
        try:
            page.evaluate(
                r"""(birthday) => {
                  const hidden = document.querySelector('input[name="birthday"], input[name="birthdate"]');
                  if (hidden) {
                    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                    if (setter) setter.call(hidden, birthday); else hidden.value = birthday;
                    hidden.dispatchEvent(new Event('input', {bubbles:true}));
                    hidden.dispatchEvent(new Event('change', {bubbles:true}));
                  }
                }""",
                birthday,
            )
        except Exception:
            pass
    return ok


def _human_complete_profile(page, name: str, birthday: str) -> dict:
    """Humanized filling of the profile page: scroll, click, type character by character, select/enter the birthday, click the checkbox and submit."""
    info: dict[str, Any] = {"ok": False, "submitted": False, "method": "human_playwright", "filled": {}}

    name_ok = _fill_first(
        page,
        [
            "input[name*='name' i]",
            "input[id*='name' i]",
            "input[autocomplete='name']",
            "input[aria-label*='name' i]",
            "input[placeholder*='name' i]",
            "input[aria-label*='名前']",
            "input[placeholder*='名前']",
            "input[aria-label*='姓名']",
            "input[placeholder*='姓名']",
            "input[type='text']",
        ],
        name,
        timeout_ms=7000,
        typing_delay_range=_cloud_typing_delay("name"),
        per_char=True,
    )
    info["filled"]["name"] = bool(name_ok)
    _human_pause(0.35, 0.9)

    try:
        _fill_birthday_fields(page, birthday)
        info["filled"]["birthday"] = True
    except Exception as exc:
        info["birthday_error"] = f"{type(exc).__name__}: {exc}"
        info["filled"]["birthday"] = False

    spin_ok = False
    try:
        spin_ok = _fill_spinbutton_birthday(page, birthday)
    except Exception:
        spin_ok = False
    if spin_ok:
        info["filled"]["spinbutton"] = True

    # Tick the visible checkbox with a real locator click, not by changing checked through JS.
    checkbox_count = 0
    try:
        boxes = page.locator("input[type='checkbox'], [role='checkbox']")
        count = min(boxes.count(), 6)
        for i in range(count):
            box = boxes.nth(i)
            try:
                if not box.is_visible(timeout=500):
                    continue
                checked = False
                try:
                    checked = bool(box.is_checked(timeout=300))
                except Exception:
                    checked = str(box.get_attribute("aria-checked") or "").lower() == "true"
                if not checked:
                    _human_click_locator(box, timeout=1500)
                    checkbox_count += 1
                    _human_pause(0.25, 0.7)
            except Exception:
                continue
    except Exception:
        pass
    info["checkboxCount"] = checkbox_count

    submitted = _click_first(
        page,
        [
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Continue')",
            "button:has-text('Next')",
            "button:has-text('Done')",
            "button:has-text('Submit')",
            "button:has-text('Create')",
            "button:has-text('Start')",
            "button:has-text('続行')",
            "button:has-text('次へ')",
            "button:has-text('完了')",
            "button:has-text('送信')",
            "button:has-text('继续')",
            "button:has-text('下一步')",
            "button:has-text('完成')",
            "button:has-text('提交')",
            "form button",
        ],
        timeout_ms=8000,
    )
    if not submitted:
        _human_pause(0.2, 0.55)
        try:
            page.keyboard.press("Enter")
            submitted = True
            info["method"] = "human_enter"
        except Exception:
            submitted = False
    info["submitted"] = bool(submitted)
    info["ok"] = bool(name_ok and submitted)
    info["url"] = _page_url(page)
    return info


def _js_complete_profile(page, name: str, birthday: str) -> dict:
    """JS Fallback handling of about-you/profile: fill name/age/birthday/checkbox and submit."""
    try:
        year, month, day = [int(x) for x in birthday.split("-")]
    except Exception:
        year, month, day = 1995, 1, 1
    today = date.today()
    age = max(18, min(60, today.year - year - ((today.month, today.day) < (month, day))))
    script = r"""
    ({name, birthday, year, month, day, age}) => {
      const month2 = String(month).padStart(2, '0');
      const day2 = String(day).padStart(2, '0');
      const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
        && !el.disabled && !el.readOnly;
      const setValue = (el, value) => {
        if (!el) return false;
        try { el.scrollIntoView?.({block:'center'}); el.focus?.(); } catch(e) {}
        const tag = (el.tagName || '').toLowerCase();
        const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype
          : tag === 'select' ? HTMLSelectElement.prototype
          : HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
        if (setter) setter.call(el, String(value)); else el.value = String(value);
        if (tag === 'select') {
          [...el.options].forEach(opt => { opt.selected = String(opt.value) === String(value) || String(opt.textContent || '').trim() === String(value); });
        }
        el.dispatchEvent(new Event('input', {bubbles:true}));
        el.dispatchEvent(new Event('change', {bubbles:true}));
        try { el.blur?.(); } catch(e) {}
        return true;
      };
      const hay = el => [el.name, el.id, el.placeholder, el.getAttribute('aria-label'), el.autocomplete, el.getAttribute('data-testid')].join(' ').toLowerCase();
      const allInputs = [...document.querySelectorAll('input, textarea')].filter(visible);
      const filled = {};

      const nameInput = allInputs.find(el => /(name|full.?name|user.?name|名前|氏名|姓名)/i.test(hay(el)) && !/(month|day|year|age|birth|code|email|phone|password)/i.test(hay(el)))
        || allInputs.find(el => ['text',''].includes((el.type||'').toLowerCase()) && !/(code|email|phone|tel|number|password|month|day|year|age|birth)/i.test(hay(el)));
      if (nameInput) filled.name = setValue(nameInput, name);

      const firstLast = name.split(/\s+/, 2);
      const firstInput = allInputs.find(el => /(first.?name|given)/i.test(hay(el)));
      const lastInput = allInputs.find(el => /(last.?name|family|surname)/i.test(hay(el)));
      if (!filled.name && firstInput) filled.firstName = setValue(firstInput, firstLast[0] || name);
      if (lastInput) filled.lastName = setValue(lastInput, firstLast[1] || 'User');

      const ageInput = allInputs.find(el => /(age|年齢|年龄)/i.test(hay(el)) || ((el.type||'').toLowerCase()==='number' && !/(day|month|year)/i.test(hay(el))));
      if (ageInput) filled.age = setValue(ageInput, age);

      const dateInput = [...document.querySelectorAll('input[name="birthdate"], input[type="date"], input[name="birthday"]')]
        .find(el => visible(el) || String(el.getAttribute('type') || '').toLowerCase() === 'date');
      if (dateInput) filled.birthdate = setValue(dateInput, birthday);

      const setFirst = (selectors, values, key) => {
        for (const sel of selectors) for (const el of [...document.querySelectorAll(sel)]) {
          if (!visible(el)) continue;
          for (const val of values) {
            if ((el.tagName || '').toLowerCase() === 'select') {
              const has = [...el.options].some(o => String(o.value) === String(val) || String(o.textContent || '').trim() === String(val));
              if (!has) continue;
            }
            if (setValue(el, val)) { filled[key] = val; return true; }
          }
        }
        return false;
      };
      const yOk = setFirst(['select[name="year"]','input[name="year"]','select[id*="year"]','input[id*="year"]','input[aria-label*="year" i]'], [year], 'year');
      const mOk = setFirst(['select[name="month"]','input[name="month"]','select[id*="month"]','input[id*="month"]','input[aria-label*="month" i]'], [month, month2], 'month');
      const dOk = setFirst(['select[name="day"]','input[name="day"]','select[id*="day"]','input[id*="day"]','input[aria-label*="day" i]'], [day, day2], 'day');
      if (yOk && mOk && dOk) {
        const hidden = document.querySelector('input[name="birthday"],input[name="birthdate"]');
        if (hidden) setValue(hidden, birthday);
        filled.ymd = true;
      }

      // React Aria hidden native select: infer year/month/day from the option range, not depending on text.
      const selects = [...document.querySelectorAll('[data-testid="hidden-select-container"] select, .react-aria-Select select, select')]
        .filter(el => !el.disabled);
      const nums = sel => [...sel.options].map(o => Number(o.value)).filter(Number.isFinite);
      const maxNum = sel => Math.max(...nums(sel), -Infinity);
      const minNum = sel => Math.min(...nums(sel), Infinity);
      const hasOption = (sel, val) => [...sel.options].some(o => String(o.value) === String(val));
      const yearSelects = selects.filter(sel => hasOption(sel, year) && maxNum(sel) > 1900);
      const smallSelects = selects.filter(sel => !yearSelects.includes(sel));
      const monthSelects = smallSelects.filter(sel => (hasOption(sel, month) || hasOption(sel, month2)) && minNum(sel) <= 1 && maxNum(sel) <= 12);
      const daySelects = smallSelects.filter(sel => (hasOption(sel, day) || hasOption(sel, day2)) && maxNum(sel) >= 28);
      let birthMode = filled.age ? 'age' : (filled.birthdate ? 'birthdate' : (filled.ymd ? 'ymd' : null));
      if (!birthMode && yearSelects.length && monthSelects.length && daySelects.length) {
        const ys = yearSelects[0];
        const ms = monthSelects[0];
        const ds = daySelects.find(x => x !== ms) || daySelects[0];
        setValue(ys, year);
        setValue(ms, hasOption(ms, month) ? month : month2);
        setValue(ds, hasOption(ds, day) ? day : day2);
        const hidden = document.querySelector('input[name="birthday"],input[name="birthdate"]');
        if (hidden) setValue(hidden, birthday);
        filled.reactSelect = true;
        birthMode = 'react_select';
      }
      if (!birthMode && document.querySelector('[role="spinbutton"][data-type="year"]')) birthMode = 'spinbutton_needed';

      const isChecked = el => el.checked === true || String(el.getAttribute('aria-checked') || el.closest('[role="checkbox"]')?.getAttribute('aria-checked') || '').toLowerCase() === 'true';
      const mark = el => {
        if (!el || isChecked(el)) return false;
        const label = el.closest('label');
        try { (label && visible(label) ? label : el).scrollIntoView({block:'center'}); (label && visible(label) ? label : el).click(); } catch(e) {}
        if (!isChecked(el)) {
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set;
          if (setter) setter.call(el, true); else el.checked = true;
          el.dispatchEvent(new MouseEvent('click', {bubbles:true}));
          el.dispatchEvent(new Event('input', {bubbles:true}));
          el.dispatchEvent(new Event('change', {bubbles:true}));
        }
        return isChecked(el);
      };
      let checkboxCount = 0;
      for (const box of [...document.querySelectorAll('input[type="checkbox"]')].filter(el => visible(el) || visible(el.closest('label')))) {
        if (mark(box)) checkboxCount += 1;
      }

      const clickSubmit = () => {
        const forms = [...document.querySelectorAll('form')].filter(el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        for (const form of forms) {
          const submit = form.querySelector('button[type="submit"], input[type="submit"]');
          if (submit && visible(submit) && !submit.disabled && submit.getAttribute('aria-disabled') !== 'true') {
            submit.scrollIntoView({block:'center'}); submit.click(); return {clicked:true, method:'form_submit_button', text:(submit.innerText||submit.value||'').trim()};
          }
        }
        const buttons = [...document.querySelectorAll('button,input[type="submit"],[role="button"]')].filter(visible);
        const scored = buttons.map((el, idx) => {
          const t = [el.innerText, el.textContent, el.value, el.getAttribute('aria-label'), el.type].join(' ').toLowerCase();
          let score = 0;
          if (el.disabled || el.getAttribute('aria-disabled') === 'true') score = -100;
          else if ((el.type || '').toLowerCase() === 'submit') score = 95;
          else if (/(continue|next|done|submit|create|start|続行|次へ|完了|送信|開始|继续|下一步|完成|提交)/i.test(t)) score = 90;
          else if (buttons.length === 1) score = 50;
          return {el, idx, score, text:(el.innerText||el.textContent||el.value||'').trim()};
        }).filter(x => x.score > 0).sort((a,b) => b.score - a.score || a.idx - b.idx);
        if (scored.length) { scored[0].el.scrollIntoView({block:'center'}); scored[0].el.click(); return {clicked:true, method:'button', text:scored[0].text}; }
        for (const form of forms) {
          if (typeof form.requestSubmit === 'function') { form.requestSubmit(); return {clicked:true, method:'requestSubmit'}; }
        }
        return {clicked:false, method:'none'};
      };
      const submit = clickSubmit();
      return {
        ok: Boolean((filled.name || filled.firstName) && birthMode),
        submitted: submit.clicked,
        method: submit.method,
        buttonText: submit.text || '',
        birthMode,
        checkboxCount,
        filled,
        url: location.href,
        buttons: [...document.querySelectorAll('button,input[type="submit"],[role="button"]')].map(el => ({text:(el.innerText||el.textContent||el.value||'').trim().slice(0,80), disabled:!!el.disabled || el.getAttribute('aria-disabled')==='true'})).slice(0,10),
      };
    }
    """
    try:
        return page.evaluate(script, {"name": name, "birthday": birthday, "year": year, "month": month, "day": day, "age": age}) or {}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "url": _page_url(page)}


def _force_exit_profile_page(page, deadline: float) -> bool:
    """If still stuck on about-you/profile after the profile page is submitted, force a jump out, so the Skyvern remote page does not wait forever."""
    targets = [
        "https://chatgpt.com/",
        "https://chatgpt.com/auth/login",
    ]
    attempt = 0
    while time.time() < deadline:
        _check_manual_stop()
        attempt += 1
        try:
            url = _page_url(page).lower()
        except Exception:
            url = ""
        if "chatgpt.com" in url and "about-you" not in url and "signup/profile" not in url and "auth.openai.com" not in url:
            return True
        if _has_chatgpt_access_token(page):
            return True
        for target in targets:
            if time.time() >= deadline:
                break
            try:
                logger.info("[BrowserUse] Still not left after the profile page was submitted, forced jump fallback:attempt=%s target=%s current=%s", attempt, target, _page_url(page) or "-")
                page.goto(target, wait_until="domcontentloaded", timeout=10000)
                _bu_delay("navigate")
                _maybe_dismiss_chatgpt_onboarding(page)
                if _has_chatgpt_access_token(page):
                    return True
                url = _page_url(page).lower()
                if "chatgpt.com" in url and "about-you" not in url and "signup/profile" not in url and "auth.openai.com" not in url:
                    return True
            except Exception as exc:
                logger.warning("[BrowserUse] Failed to force-jump out of the profile page:%s: %s", type(exc).__name__, str(exc)[:180])
        time.sleep(0.8 if _fast_mode() else 1.2)
    return False


def _complete_profile_page(page, name: str, birthday: str, timeout: int = 60) -> bool:
    """Profile page fill/submit: do not wait forever after submitting; force a jump out of about-you when Skyvern hangs."""

    timeout = min(timeout, 45) if _fast_mode() else timeout
    end = time.time() + timeout
    submitted = False
    last_submit = 0.0
    last_log = 0.0
    last_info: dict[str, Any] = {}
    last_diag: dict[str, Any] = {}
    post_submit_hard_exit_at: float | None = None

    while time.time() < end:
        _check_manual_stop()
        url = _page_url(page).lower()
        if "chatgpt.com" in url and "auth.openai.com" not in url and "about-you" not in url and "signup/profile" not in url:
            logger.info("[BrowserUse] Left the profile page and entered ChatGPT:%s", _page_url(page))
            return True
        if _has_chatgpt_access_token(page):
            logger.info("[BrowserUse] Detected after the profile page was submitted accessToken")
            return True

        body = ""
        try:
            body = (page.locator("body").inner_text(timeout=800) or "").lower()
        except Exception:
            pass
        looks_profile = any(x in url for x in ("about-you", "profile", "create-account/about", "signup/profile")) or any(x in body for x in ("birthday", "birth", "age", "name", "誕生日", "年齢", "名前", "生日", "年龄", "姓名"))

        if looks_profile:
            if not submitted:
                logger.info("[BrowserUse] Profile page: fill/submit nickname and birthday url=%s", _page_url(page) or "-")
                info = _human_complete_profile(page, name, birthday)
                last_info = info
                logger.info("[BrowserUse] Humanized profile page submit result:%s", str(info)[:900])
                if not info.get("submitted"):
                    js_info = _js_complete_profile(page, name, birthday)
                    last_info = {"human": info, "js": js_info}
                    logger.info("[BrowserUse] Profile page JS fallback submit result:%s", str(js_info)[:900])
                    submitted = bool(js_info.get("submitted") or submitted)
                else:
                    submitted = True
                if submitted and post_submit_hard_exit_at is None:
                    # After submitting, do not fill/click again; give it at most 10~16 seconds to sync the login state, then force a jump out.
                    post_submit_hard_exit_at = time.time() + (10 if _fast_mode() else 16)
                last_submit = time.time()
                _bu_delay("form")
            elif time.time() - last_log > 2:
                logger.info("[BrowserUse] Profile page submitted, waiting for a short jump / preparing to get the AT:url=%s", _page_url(page) or "-")
                last_log = time.time()

            if submitted and post_submit_hard_exit_at and time.time() >= post_submit_hard_exit_at:
                if _force_exit_profile_page(page, min(end, time.time() + (8 if _fast_mode() else 12))):
                    logger.info("[BrowserUse] Exited via forced jump after the profile page was submitted:%s", _page_url(page) or "-")
                    return True
                break
            time.sleep(0.35 if _fast_mode() else 0.8)
            continue

        if submitted:
            if _has_chatgpt_access_token(page):
                logger.info("[BrowserUse] Detected after the profile page was submitted accessToken")
                return True
            if post_submit_hard_exit_at is None:
                post_submit_hard_exit_at = time.time() + (10 if _fast_mode() else 16)
            if time.time() - last_log > 2:
                logger.info("[BrowserUse] Profile page submitted, waiting for the login state to sync:url=%s", _page_url(page) or "-")
                last_log = time.time()
            if time.time() >= post_submit_hard_exit_at:
                if _force_exit_profile_page(page, min(end, time.time() + (8 if _fast_mode() else 12))):
                    logger.info("[BrowserUse] Exited via forced jump after the profile page was submitted:%s", _page_url(page) or "-")
                    return True
                break
            time.sleep(0.35 if _fast_mode() else 0.8)
            continue

        if time.time() - last_log > 2:
            logger.info("[BrowserUse] Waiting for the profile page / login state:url=%s", _page_url(page) or "-")
            last_log = time.time()
        time.sleep(0.25 if _fast_mode() else 0.6)

    url = _page_url(page).lower()
    if any(x in url for x in ("about-you", "profile", "create-account/about", "signup/profile")):
        last_diag = _profile_diagnostics(page)
        if submitted:
            raise RuntimeError(f"Still no jump after the profile page was submitted and timed out, moving on to get the AT;last_info={str(last_info)[:900]} diag={str(last_diag)[:1200]}")
        raise RuntimeError(f"Profile page handling timed out and the submit was not confirmed, moving on to get the AT;last_info={str(last_info)[:900]} diag={str(last_diag)[:1200]}")
    return submitted


def _is_target_closed_error(exc: Exception | str) -> bool:
    text = str(exc).lower()
    return any(x in text for x in ("targetclosed", "target page", "context or browser has been closed", "browser has been closed", "page.is_closed"))


def _is_transient_navigation_error(exc: Exception | str) -> bool:
    text = str(exc).lower()
    return any(x in text for x in (
        "execution context was destroyed",
        "most likely because of a navigation",
        "navigation",
        "frame was detached",
    ))


def _pick_live_page(context, preferred=None):
    """Browser Use The remote sometimes opens/switches targets; prefer the live page that is on the verification code / password / profile page."""
    pages = []
    try:
        for p in list(context.pages):
            try:
                if not p.is_closed():
                    pages.append(p)
            except Exception:
                continue
    except Exception:
        pass
    if preferred is not None:
        try:
            if not preferred.is_closed() and preferred not in pages:
                pages.insert(0, preferred)
        except Exception:
            pass
    if not pages:
        return None
    if len(pages) == 1:
        return pages[0]

    rank = {
        "email_verification": 100,
        "password": 90,
        "profile": 80,
        "chatgpt": 70,
        "login_password": 60,
        "other": 10,
    }
    best = pages[0]
    best_info = {"state": "other", "url": _page_url(best)}
    best_rank = -1
    inventory = []
    for idx, p in enumerate(pages):
        try:
            info = _quick_auth_state(p)
        except Exception:
            info = {"state": "other", "url": _page_url(p), "error": "state_failed"}
        state = str(info.get("state") or "other")
        score = rank.get(state, 0)
        if p is preferred:
            score += 1
        inventory.append(f"#{idx}:{state}:{str(info.get('url') or '-')[:120]}")
        if score > best_rank:
            best = p
            best_info = info
            best_rank = score
    if best is not preferred:
        logger.info(
            "[BrowserUse] Switched to a better matching page:state=%s url=%s pages=%s",
            best_info.get("state") or "-",
            best_info.get("url") or "-",
            inventory,
        )
    return best


def _browser_use_heartbeat(page, context=None, label: str = ""):
    """Do a lightweight heartbeat on the Browser Use cloud page and probe along the way whether the target has been closed by the platform.

    OpenAI navigation often closes the old target and opens a new page; here when closed we retry briefly and switch to the live page,
    to avoid misjudging normal navigation as "session is dead".
    """
    tag = f"({label})" if label else ""

    def _inventory() -> str:
        if context is None:
            return "no-context"
        items = []
        try:
            for idx, p in enumerate(list(context.pages)):
                try:
                    closed = p.is_closed()
                except Exception:
                    closed = True
                items.append(f"#{idx}:{'closed' if closed else 'open'}:{_page_url(p)[:100]}")
        except Exception as exc:
            return f"inventory-failed:{type(exc).__name__}"
        return items and "; ".join(items) or "no-pages"

    def _recover_live(preferred=None):
        if context is None:
            return None
        # pages may be briefly empty at the moment of navigation, wait a moment and fetch again
        for delay in (0.0, 0.35, 0.8):
            if delay:
                time.sleep(delay)
            live = _pick_live_page(context, preferred)
            if live is None:
                continue
            try:
                if live.is_closed():
                    continue
            except Exception:
                continue
            return live
        return None

    if context is not None:
        live = _pick_live_page(context, page)
        if live is not None:
            page = live
    if page is None:
        page = _recover_live(None)
    if page is None:
        raise RuntimeError(f"BrowserUse Page closed, cannot continue the heartbeat{tag};pages={_inventory()}")

    try:
        if page.is_closed():
            recovered = _recover_live(page)
            if recovered is None:
                raise RuntimeError(f"BrowserUse page.is_closed()=True{tag};pages={_inventory()}")
            page = recovered
            logger.info("[BrowserUse] Heartbeat recovered to a live page%s:url=%s", tag, _page_url(page) or "-")
    except Exception as exc:
        if _is_target_closed_error(exc):
            recovered = _recover_live(None)
            if recovered is None:
                raise RuntimeError(f"BrowserUse Page closed, cannot continue the heartbeat{tag}: {exc};pages={_inventory()}") from exc
            page = recovered
            logger.info("[BrowserUse] target Switched to a live page after closing%s:url=%s", tag, _page_url(page) or "-")
        else:
            raise

    try:
        # Reading location/visibilityState is light enough and does not change the page state; it keeps the remote page target alive better than context.request.
        page.evaluate("() => ({href: location.href, visibility: document.visibilityState, t: Date.now()})", timeout=2500)
    except TypeError:
        # Compatible with old Playwright: evaluate does not support the timeout parameter.
        try:
            page.evaluate("() => ({href: location.href, visibility: document.visibilityState, t: Date.now()})")
        except Exception as exc:
            if _is_target_closed_error(exc):
                recovered = _recover_live(None)
                if recovered is None:
                    raise RuntimeError(f"BrowserUse Page closed, cannot continue the heartbeat{tag}: {exc};pages={_inventory()}") from exc
                page = recovered
                logger.info("[BrowserUse] evaluate Switched to a live page after closing%s:url=%s", tag, _page_url(page) or "-")
            else:
                logger.debug("[BrowserUse] Heartbeat failed%s:%s", tag, str(exc)[:180])
    except Exception as exc:
        if _is_target_closed_error(exc):
            recovered = _recover_live(None)
            if recovered is None:
                raise RuntimeError(f"BrowserUse Page closed, cannot continue the heartbeat{tag}: {exc};pages={_inventory()}") from exc
            page = recovered
            logger.info("[BrowserUse] evaluate Switched to a live page after closing%s:url=%s", tag, _page_url(page) or "-")
        else:
            logger.debug("[BrowserUse] Heartbeat failed%s:%s", tag, str(exc)[:180])
    return page



def _wait_for_otp_with_browser_heartbeat(page, context, email: str, after_ts: float) -> str:
    """Short polling of the email OTP; touch the page between rounds, so Browser Use Cloud does not reclaim the session after a long time without page activity."""
    try:
        from config import email as _email_cfg
        total_wait = int(getattr(_email_cfg, "OTP_MAX_WAIT", 90) or 90)
        poll_interval = int(getattr(_email_cfg, "OTP_POLL_INTERVAL", 3) or 3)
        settle = int(getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5) or 0)
    except Exception:
        total_wait, poll_interval, settle = 90, 3, 5

    # A single email poll must not block for too long, otherwise the cloud browser has no page activity at all during that time.
    # But with occasional TLS/network jitter in Outlook direct/Graph, a 12s slice is too short and the round is judged timed out by the upper layer before
    # Graph/REST/IMAP the fallback can complete; here it is relaxed to at most 30s, and a page heartbeat is still done between rounds.
    slice_wait = max(15, min(30, total_wait))
    slice_settle = max(0, min(settle, 5))
    deadline = time.time() + total_wait
    last_exc: Exception | None = None
    attempt = 0

    while time.time() < deadline:
        _check_manual_stop()
        attempt += 1
        page = _browser_use_heartbeat(page, context=context, label=f"otp-before-{attempt}")
        remaining = max(1, int(deadline - time.time()))
        wait_this_round = min(slice_wait, remaining)
        logger.info(
            "[BrowserUse][OTP] Email short poll: %s, round %s, up to %ss (total remaining %ss)",
            email,
            attempt,
            wait_this_round,
            remaining,
        )
        try:
            return wait_for_otp(
                email,
                after_ts=after_ts,
                max_wait=wait_this_round,
                poll_interval=max(1, min(poll_interval, 3)),
                settle_seconds=slice_settle,
            )
        except Exception as exc:
            last_exc = exc
            if _is_target_closed_error(exc):
                raise
            if time.time() >= deadline:
                break
            logger.info("[BrowserUse][OTP] No verification code obtained this round, keeping the cloud page active and continuing:%s: %s", type(exc).__name__, str(exc)[:220])
            page = _browser_use_heartbeat(page, context=context, label=f"otp-after-{attempt}")
            time.sleep(0.5 if _fast_mode() else 1.0)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"Timed out waiting for the OTP of {email} (>{total_wait}s)")


def _read_chatgpt_session_via_context(context, timeout_ms: int = 5000) -> dict | None:
    """Read the session with BrowserContext.request; the context cookies are shared, no dependence on page evaluate."""
    try:
        resp = context.request.get(
            "https://chatgpt.com/api/auth/session",
            timeout=timeout_ms,
            headers={
                "accept": "application/json",
                "referer": "https://chatgpt.com/",
                "cache-control": "no-cache",
            },
        )
        try:
            data = resp.json()
        except Exception:
            data = {"status": resp.status, "text": (resp.text() or "")[:500]}
        if isinstance(data, dict):
            data.setdefault("_http_status", resp.status)
        return data
    except Exception as exc:
        return {"_error": f"{type(exc).__name__}: {exc}"}


def _read_chatgpt_session_via_page(page, timeout_ms: int = 5000) -> dict | None:
    """Read the session inside the page with a JS AbortController added, so page.evaluate does not hang forever."""
    try:
        page.set_default_timeout(max(2000, timeout_ms + 1000))
    except Exception:
        pass
    try:
        return page.evaluate(
            """async ({timeoutMs}) => {
              const ctrl = new AbortController();
              const timer = setTimeout(() => ctrl.abort('session-timeout'), timeoutMs);
              try {
                const r = await fetch('/api/auth/session', {
                  credentials: 'include',
                  cache: 'no-store',
                  headers: {'accept': 'application/json'},
                  signal: ctrl.signal,
                });
                const j = await r.json().catch(async () => ({text: await r.text()}));
                if (j && typeof j === 'object') j._http_status = r.status;
                return j;
              } finally {
                clearTimeout(timer);
              }
            }""",
            {"timeoutMs": timeout_ms},
        )
    except Exception as exc:
        return {"_error": f"{type(exc).__name__}: {exc}"}

def _fetch_chatgpt_session(page, context=None, timeout: int = 120) -> dict:
    # Prefer BrowserContext.request to read cookies/session, so page.evaluate does not hang on a Browser Use remote target.
    timeout = min(timeout, 28) if _fast_mode() else timeout
    end = time.time() + timeout
    last = None
    proactive_opened = False
    first_not_chatgpt_at: float | None = None
    first_profile_still_at: float | None = None
    last_log = 0.0
    target_closed_count = 0

    if context is None:
        try:
            context = page.context
        except Exception:
            context = None

    while time.time() < end:
        _check_manual_stop()
        if context is not None:
            live = _pick_live_page(context, page)
            if live is not None and live is not page:
                logger.info("[BrowserUse] The current page is closed/unavailable, switching to an available page of the same context:url=%s", _page_url(live) or "-")
                page = live

        url = _page_url(page).lower() if page is not None else ""
        on_chatgpt = "chatgpt.com" in url

        # 1) context.request Read first: fast and independent of page JS; even if the page target is closed, as long as the context is alive it can still be read.
        if context is not None:
            data = _read_chatgpt_session_via_context(context, timeout_ms=1800 if _fast_mode() else 5000)
            last = data
            if isinstance(data, dict) and data.get("accessToken"):
                logger.info("[BrowserUse] /api/auth/session returned accessToken via=context url=%s", _page_url(page) or "-")
                return data
            err = str((data or {}).get("_error") or "") if isinstance(data, dict) else ""
            if err and _is_target_closed_error(err):
                target_closed_count += 1
                if target_closed_count >= 2:
                    raise RuntimeError(f"BrowserUse context/page is closed, cannot read the session:{err}")
            if time.time() - last_log > 2:
                keys = list((data or {}).keys()) if isinstance(data, dict) else type(data)
                logger.info("[BrowserUse] Waiting for accessToken via=context,url=%s keys=%s", _page_url(page) or "-", keys)
                last_log = time.time()

        # 2) If already on chatgpt.com, fall back to an in-page fetch, but with a short timeout.
        if on_chatgpt and page is not None:
            _maybe_dismiss_chatgpt_onboarding(page)
            data = _read_chatgpt_session_via_page(page, timeout_ms=2200 if _fast_mode() else 5000)
            last = data
            if isinstance(data, dict) and data.get("accessToken"):
                logger.info("[BrowserUse] /api/auth/session returned accessToken via=page url=%s", _page_url(page) or "-")
                return data
            err = str((data or {}).get("_error") or "") if isinstance(data, dict) else ""
            if err and _is_target_closed_error(err):
                target_closed_count += 1
                logger.warning("[BrowserUse] The page target is closed, trying to keep reading the session through the context:%s", err[:180])
                if context is None or _pick_live_page(context) is None:
                    # Do not wait until the total timeout any more; the BrowserUse remote target is gone and waiting longer is meaningless.
                    raise RuntimeError(f"BrowserUse Page closed, cannot read the session:{err}")
            elif time.time() - last_log > 2:
                keys = list((data or {}).keys()) if isinstance(data, dict) else type(data)
                logger.info("[BrowserUse] Waiting for accessToken via=page,url=%s keys=%s", _page_url(page) or "-", keys)
                last_log = time.time()
        else:
            # After the profile page is submitted Skyvern occasionally does not jump automatically; reaching the session stage means the profile handling is already over,
            # staying on about-you/profile is meaningless, so after a brief look force a jump to ChatGPT to read the login state.
            if any(x in url for x in ("about-you", "profile", "create-account/about", "signup/profile")):
                if first_profile_still_at is None:
                    first_profile_still_at = time.time()
                if time.time() - first_profile_still_at >= (3.0 if _fast_mode() else 6.0):
                    if _force_exit_profile_page(page, min(end, time.time() + (8 if _fast_mode() else 12))):
                        proactive_opened = True
                        continue
                if time.time() - last_log > 2:
                    logger.info("[BrowserUse] session stage is still on the profile page, will force a jump out after a short wait:url=%s", _page_url(page) or "-")
                    last_log = time.time()
                time.sleep(0.4 if _fast_mode() else 1.0)
                continue
            if first_not_chatgpt_at is None:
                first_not_chatgpt_at = time.time()
            wait_before_open = 2.0 if _fast_mode() else 8.0
            if page is not None and _fast_mode() and not proactive_opened and time.time() - first_not_chatgpt_at >= wait_before_open:
                logger.info("[BrowserUse] Did not quickly jump to chatgpt.com automatically, actively opening the home page to read the session:current=%s", _page_url(page) or "-")
                try:
                    page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=_timeout_ms(getattr(_cfg, "BROWSER_USE_NAVIGATION_TIMEOUT", 90)))
                    proactive_opened = True
                    _bu_delay("navigate")
                    _maybe_dismiss_chatgpt_onboarding(page)
                    continue
                except Exception as exc:
                    last = f"goto_chatgpt_failed {type(exc).__name__}: {exc}"
                    if _is_target_closed_error(exc):
                        target_closed_count += 1
                        if context is None or _pick_live_page(context) is None:
                            raise RuntimeError(f"BrowserUse Page closed, cannot actively open ChatGPT:{last}")
            if time.time() - last_log > 2:
                logger.info("[BrowserUse] Waiting to enter chatgpt.com or for the login state to sync:url=%s", _page_url(page) or "-")
                last_log = time.time()

        time.sleep(0.45 if _fast_mode() else 2)

    raise RuntimeError(f"Timed out waiting for the /api/auth/session accessToken, last response: {str(last)[:800]}")


def run_browser_use_registration(
    email: str | None,
    name: str,
    birthday: str,
    proxy: str | None = None,
    otp_code: str | None = None,
    batch_dir: Path | None = None,
    cloud_provider: str = "browser_use",
    on_email_acquired: Callable[[str], None] | None = None,
) -> dict:
    """Browser Use / Skyvern Cloud browser registration entry point. The proxy parameter is kept for compatibility."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "playwright is missing. Please run first: uv pip install playwright --python .venv/bin/python"
        ) from exc

    provider = str(cloud_provider or "browser_use").strip().lower()
    if provider in ("skyvern", "sv"):
        from core.skyvern_client import SkyvernClient
        cloud_label = "Skyvern"
        provider_prefix = "skyvern"
        client = SkyvernClient()
    else:
        cloud_label = "BrowserUse"
        provider_prefix = "browser_use"
        client = BrowserUseClient()

    _set_log_provider_label(cloud_label)
    _set_cloud_provider(provider_prefix)
    _t_all = _StepTimer(f"{cloud_label} full registration flow")
    session_info_open = client.open_session()
    create_acknowledged = False
    openai_password: str | None = None
    browser = None
    context = None
    page = None
    network_traffic: dict[str, Any] | None = None

    logger.info(
        "[%s] Starting registration:%s proxyCountry=%s profileId=%s local_proxy_arg=%s",
        cloud_label,
        email,
        session_info_open.proxy_country_code or "-",
        session_info_open.profile_id or "-",
        "yes" if proxy else "no",
    )

    try:
        with sync_playwright() as p:
            logger.info("[%s] Connect CDP ...", cloud_label)
            _t_cdp = _StepTimer(f"Connect {cloud_label} CDP")
            connect_kwargs = {}
            if provider_prefix == "skyvern" and hasattr(client, "cdp_headers"):
                connect_kwargs["headers"] = client.cdp_headers()
            browser = p.chromium.connect_over_cdp(session_info_open.connect_url, **connect_kwargs)
            _t_cdp.done()
            # Browser Use usually already has a default context/page
            if browser.contexts:
                context = browser.contexts[0]
            else:
                context = browser.new_context()
            page = context.pages[0] if context.pages else context.new_page()
            page.set_default_timeout(_timeout_ms())
            page.set_default_navigation_timeout(_timeout_ms(getattr(_cfg, "BROWSER_USE_NAVIGATION_TIMEOUT", 90)))
            # Browser Use/Skyvern is a cloud browser; it does not install the local traffic-saving routes, network traffic
            # listeners or JS coverage collection, ensuring the cloud page runs in the original flow without extra CDP overhead.
            logger.info("[%s] Cloud browser skips traffic saving, network listening and JS coverage collection", cloud_label)
            if _should_apply_cloud_automation_mask(provider_prefix):
                _apply_cloud_browser_automation_mask(
                    context,
                    page,
                    label=cloud_label,
                    provider_prefix=provider_prefix,
                    proxy_country_code=session_info_open.proxy_country_code,
                )
            else:
                logger.info("[%s] Extra JS fingerprint patches skipped, using the native stealth environment of the cloud browser", cloud_label)

            if provider_prefix == "skyvern":
                try:
                    from config import skyvern as _skyvern_cfg
                    start_url = str(getattr(_skyvern_cfg, "SKYVERN_START_URL", "https://chatgpt.com/auth/login") or "https://chatgpt.com/auth/login")
                except Exception:
                    start_url = "https://chatgpt.com/auth/login"
            else:
                start_url = str(getattr(_cfg, "BROWSER_USE_START_URL", "https://chatgpt.com/auth/login") or "https://chatgpt.com/auth/login")
            logger.info("[%s] Opening the login page:%s", cloud_label, start_url)
            _t_goto = _StepTimer("Open login page")
            page.goto(start_url, wait_until="domcontentloaded")
            _t_goto.done(f"url={_page_url(page) or '-'}")
            _bu_delay("navigate")
            _maybe_accept_cookies(page)
            _check_manual_stop()

            def _email_supplier_after_input() -> str:
                nonlocal email
                _check_manual_stop()
                email = acquire_email_after_input(email)
                if on_email_acquired:
                    on_email_acquired(email)
                return email

            _t_email = _StepTimer("Fill in and submit the email")
            # OpenAI may send the OTP right after the submit click, even with the email ReceivedDateTime earlier than Playwright
            # the local time at which the click function returned; record the timestamp first, together with the clock tolerance of _is_after, to avoid filtering out the first verification code.
            otp_after_ts = time.time()
            next_state = _submit_email_until_transition(
                page,
                context,
                email,
                attempts=2,
                timeout_ms=20000,
                email_supplier=_email_supplier_after_input,
            )
            _t_email.done(f"state={next_state}")
            logger.info("[BrowserUse] Submitted the email:%s", email)
            _assert_not_external_idp(page, "after submitting the email")
            _check_manual_stop()

            _t_pwd = _StepTimer("Detect/handle the password page")
            try:
                if next_state == "email_verification":
                    logger.info("[BrowserUse] The email submit entered the verification code page, trying to click 'continue with password' and set a password")
                openai_password = _fill_password_if_present(page, email, timeout=8 if _fast_mode() else 18, context=context)
                _t_pwd.done("password_set=yes" if openai_password else "password_set=no")
            except Exception as exc:
                _t_pwd.done(f"failed={type(exc).__name__}: {str(exc)[:160]}")
                raise
            _check_manual_stop()

            def _restart_email_otp_flow(reason: str) -> None:
                """
                OpenAI Clicking resend directly on the verification code page occasionally jumps to chrome-error/500.
                Here we instead re-open the registration entry and resubmit the same email to trigger a new OTP, keeping the page in a state where the verification code can be entered.
                """
                nonlocal page, otp_after_ts, openai_password
                logger.info("[BrowserUse][OTP] Re-triggering the email OTP:%s", reason)
                try:
                    _check_manual_stop()
                    page = _pick_live_page(context, page) or page
                    otp_after_ts = time.time()
                    page.goto(start_url, wait_until="domcontentloaded", timeout=_timeout_ms(getattr(_cfg, "BROWSER_USE_NAVIGATION_TIMEOUT", 90)))
                    _check_manual_stop()
                    _bu_delay("navigate")
                    _maybe_accept_cookies(page)
                    _check_manual_stop()
                    _submit_email_until_transition(
                        page,
                        context,
                        email,
                        attempts=2,
                        timeout_ms=12000 if _fast_mode() else 18000,
                    )
                    _check_manual_stop()
                    logger.info("[BrowserUse][OTP] Resubmitted the email:%s", email)
                    _assert_not_external_idp(page, "after resubmitting the email")
                    try:
                        pwd = _fill_password_if_present(page, email, timeout=6 if _fast_mode() else 10, context=context)
                        _check_manual_stop()
                        if pwd:
                            openai_password = pwd
                    except Exception as pwd_exc:
                        if _is_manual_stop_exception(pwd_exc):
                            raise
                        logger.info("[BrowserUse][OTP] Password page handling skipped/failed after restarting the OTP flow, continuing to wait for the verification code page:%s", str(pwd_exc)[:140])
                    _bu_delay("api")
                except Exception as restart_exc:
                    if _is_manual_stop_exception(restart_exc):
                        raise
                    logger.warning("[BrowserUse][OTP] Re-triggering the email OTP failed, continuing with the current page:%s: %s", type(restart_exc).__name__, str(restart_exc)[:180])

            current_otp = otp_code
            max_otp_attempts = 3
            for otp_attempt in range(1, max_otp_attempts + 1):
                # Wait for the verification code page to appear
                wait_end = time.time() + (20 if _fast_mode() else 45)
                last_verify_log = 0.0
                while time.time() < wait_end:
                    page = _browser_use_heartbeat(page, context=context, label="wait-email-verification")
                    state_info = _quick_auth_state(page)
                    state = str(state_info.get("state") or "other")
                    if "/log-in/password" in str(state_info.get("url") or _page_url(page) or "").lower() or state == "login_password":
                        raise RuntimeError(f"After submitting the email it entered the login password page; treated as a registered/unusable email and deactivated: url={state_info.get('url') or _page_url(page) or 'https://auth.openai.com/log-in/password'}")
                    if state == "email_verification":
                        logger.info("[BrowserUse][OTP] Verification code page detected:url=%s", state_info.get("url") or "-")
                        break
                    if any(x in _page_url(page).lower() for x in ("about-you", "profile", "chatgpt.com/")):
                        break
                    if time.time() - last_verify_log > 5:
                        logger.info("[BrowserUse][OTP] Waiting for the verification code input page to appear:state=%s url=%s", state, state_info.get("url") or "-")
                        last_verify_log = time.time()
                    time.sleep(0.2 if _fast_mode() else 0.4)

                if current_otp is None:
                    logger.info("[BrowserUse][OTP] Waiting for the verification code: %s (%s/%s)", email, otp_attempt, max_otp_attempts)
                    _t_otp_wait = _StepTimer("Waiting for the email OTP")
                    try:
                        current_otp = _wait_for_otp_with_browser_heartbeat(page, context, email, after_ts=otp_after_ts)
                        page = _pick_live_page(context, page) or page
                        _t_otp_wait.done()
                    except Exception as exc:
                        _t_otp_wait.done(f"failed={type(exc).__name__}: {str(exc)[:160]}")
                        if _is_manual_stop_exception(exc):
                            raise
                        if otp_attempt >= max_otp_attempts:
                            raise
                        logger.warning(
                            "[BrowserUse][OTP] No email verification code received this time, continuing to wait after re-triggering the OTP (%s/%s):%s: %s",
                            otp_attempt + 1,
                            max_otp_attempts,
                            type(exc).__name__,
                            str(exc)[:180],
                        )
                        _restart_email_otp_flow("Timed out waiting for the verification code, avoiding clicking resend which causes 500/chrome-error")
                        current_otp = None
                        continue
                logger.info("[BrowserUse][OTP] Verification code received:%s", current_otp)
                _t_otp_submit = _StepTimer("Submitting the email OTP")
                _clear_otp_inputs(page)
                _type_otp(page, current_otp)
                _bu_delay("otp_input")
                try:
                    _click_continue(page)
                except Exception as exc:
                    logger.info("[BrowserUse][OTP] Submit button not found, continuing to observe the page:%s", str(exc)[:120])
                _check_manual_stop()

                outcome = _wait_after_otp(page, timeout=6 if _fast_mode() else 12)
                _t_otp_submit.done(f"state={outcome}")
                if outcome in ("accepted", "unknown"):
                    # unknown also keep trying the profile page/session
                    break
                if otp_attempt >= max_otp_attempts:
                    raise RuntimeError("Email verification code wrong/expired repeatedly")
                logger.warning("[BrowserUse][OTP] The verification code may be invalid, re-triggering the OTP (%s/%s)", otp_attempt + 1, max_otp_attempts)
                _restart_email_otp_flow("Verification code wrong/expired or the page did not move on, avoiding clicking resend which causes 500/chrome-error")
                current_otp = None

            logger.info("[BrowserUse] Handling the profile page / login state")
            _t_profile = _StepTimer("Profile page / login state")
            if provider_prefix == "skyvern":
                profile_timeout = int(getattr(_cfg, "SKYVERN_PROFILE_TIMEOUT", 45) or 45)
                session_timeout = int(getattr(_cfg, "SKYVERN_SESSION_ACCESS_TOKEN_TIMEOUT", 35) or 35)
            else:
                profile_timeout = int(getattr(_cfg, "BROWSER_USE_PROFILE_TIMEOUT", 28 if _fast_mode() else 60) or (28 if _fast_mode() else 60))
                session_timeout = int(getattr(_cfg, "BROWSER_USE_SESSION_ACCESS_TOKEN_TIMEOUT", 18 if _fast_mode() else 60) or (18 if _fast_mode() else 60))

            try:
                profile_submitted = _complete_profile_page(page, name, birthday, timeout=profile_timeout)
                if profile_submitted:
                    create_acknowledged = True
                    _bu_delay("post_auth")
            except Exception as exc:
                # The profile page is a frequent sticking point: after a timeout / forced-exit failure do not keep sticking, go straight to getting the AT; if it cannot be obtained, the next step throws and fails.
                logger.warning("[BrowserUse] Profile page handling timed out/failed, trying to get the AT directly:%s: %s", type(exc).__name__, str(exc)[:260])

            try:
                session_info = _fetch_chatgpt_session(page, context=context, timeout=session_timeout)
                _t_profile.done()
            except Exception as exc:
                _t_profile.done(f"failed={type(exc).__name__}: {str(exc)[:160]}")
                raise
            access_token = session_info.get("accessToken")
            if not access_token:
                raise RuntimeError("Registration flow ended but no accessToken")
            create_acknowledged = True
            logger.info("[BrowserUse] Got the accessToken:%s", email)

            if _twofa_cfg.ENABLE_2FA:
                logger.warning("[BrowserUse] 2FA is not set up automatically on the current path, skipped")
            totp_secret = None

            codex_result = {
                "status": "skipped",
                "ok": True,
                "message": "ENABLE_CODEX_AUTO=False, skipping Codex",
            }
            try:
                from config import codex as _codex_cfg
                codex_auto_enabled = bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False))
                oauth_driver = str(getattr(_codex_cfg, "CODEX_OAUTH_DRIVER", "") or "").strip() or "same_as_registration"
                if codex_auto_enabled:
                    logger.info(
                        "[BrowserUse][Codex] ENABLE_CODEX_AUTO=True, automatically running Codex OAuth after a successful registration:driver=%s",
                        oauth_driver,
                    )
                    # Codex OAuth will create its own authorization session. First close the registration phase Browser Use
                    # CDP connection, so the registration browser does not keep holding remote session / proxy resources and disturb the following OAuth.
                    _close_browser_use_session(browser, reason="About to run Codex OAuth")
                    if provider_prefix == "skyvern" and hasattr(client, "close_browser_session") and getattr(session_info_open, "session_id", ""):
                        try:
                            client.close_browser_session(session_info_open.session_id)
                            logger.info("[Skyvern] Closed the registration browser session:%s", session_info_open.session_id)
                        except Exception as exc:
                            logger.warning("[Skyvern] Failed to close the registration browser session:%s: %s", type(exc).__name__, str(exc)[:180])
                    browser = None
                    context = None
                    page = None
                    from core.codex_oauth import run_codex_oauth
                    codex_result = run_codex_oauth(email, otp_provider=wait_for_otp, proxy=proxy, force=True)
                else:
                    logger.info("[BrowserUse][Codex] ENABLE_CODEX_AUTO=False, skipping after registration Codex OAuth")
            except Exception as exc:
                logger.warning("[BrowserUse][Codex] Automatic authorization failed:%s: %s", type(exc).__name__, str(exc)[:220])
                codex_result = {
                    "status": "failed",
                    "ok": False,
                    "message": f"{type(exc).__name__}: {str(exc)[:220]}",
                }

            # Cloud browsers do not collect local traffic details; the dwell after registration is only used to complete the page flow.
            _post_register_dwell(page, context, provider_prefix=provider_prefix, email=email)
            account_id = save_account_data(
                email=email,
                access_token=access_token,
                totp_secret=totp_secret,
                email_source=resolve_email_source(email),
                proxy_used=proxy or f"{provider_prefix}:{session_info_open.proxy_country_code or 'default'}",
                batch_dir=batch_dir,
                extra={
                    "user": session_info.get("user"),
                    "account": session_info.get("account"),
                    "expires": session_info.get("expires"),
                    provider_prefix: {
                        "proxy_country_code": session_info_open.proxy_country_code,
                        "profile_id": session_info_open.profile_id,
                        "session_id": getattr(session_info_open, "session_id", ""),
                        "connect": session_info_open.raw,
                    },
                    "registration_password": openai_password,
                    "codex": codex_result,
                    "network_traffic": network_traffic,
                },
            )
            _t_all.done("success")
            return {
                "success": True,
                "email": email,
                "account_id": account_id,
                "access_token": access_token,
                "totp_secret": totp_secret,
                "codex": codex_result,
                "network_traffic": network_traffic,
                "error": None,
            }
    except Exception as exc:
        logger.error("[BrowserUse] Registration failed:%s: %s", type(exc).__name__, exc)
        logger.debug("[BrowserUse] failure details", exc_info=True)
        try:
            if email:
                from core.email_provider import release_email
                release_email(
                    email,
                    status="failed" if create_acknowledged else "available",
                    note=f"BrowserUse registration failed: {str(exc)[:180]}",
                )
        except Exception:
            pass
        return {
            "success": False,
            "email": email,
            "network_traffic": network_traffic,
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
        }
    finally:
        # Close the connection uniformly when the task ends, to avoid leftover cloud browser / CDP occupying resources.
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass
        if provider_prefix == "skyvern" and 'client' in locals() and hasattr(client, "close_browser_session") and getattr(session_info_open, "session_id", ""):
            try:
                client.close_browser_session(session_info_open.session_id)
            except Exception:
                pass
        _set_log_provider_label("BrowserUse")
        _set_cloud_provider("browser_use")
