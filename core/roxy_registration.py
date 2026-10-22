# -*- coding: utf-8 -*-
"""Run the ChatGPT registration through the RoxyBrowser fingerprint browser + Selenium."""
from __future__ import annotations

import logging
import random
import string
import time
import uuid
from pathlib import Path
from typing import Callable

from config import roxybrowser as _cfg
from config import twofa as _twofa_cfg
from core.account_export import save_account_data, post_register_dwell
from core.browser_data_saver import BrowserDataSaver
from core.browser_traffic import SeleniumTrafficTracker, merge_proxy_transport_traffic
from core.roxy_asset_cache import RoxyLocalAssetCache
from core.email_provider import acquire_email_after_input, wait_for_otp, resolve_email_source
from core.humanize import delay as human_delay
from core.roxybrowser_client import RoxyBrowserClient, RoxyOpenResult

logger = logging.getLogger(__name__)


def _enable_performance_logging(options) -> None:
    """Enable the Chrome performance log where possible; registration is not blocked when it is unsupported."""
    try:
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    except Exception as exc:
        logger.debug("[Roxy] The current Selenium options do not support the performance log:%s", exc)


def _log_prefix(driver=None) -> str:
    """Return the registration log prefix according to the current browser implementation.

    CloakBrowser reuses the Roxy page operation functions; these shared functions must follow the actual driver and driver
    output `[Cloak registration]`, so `[Roxy registration]` logs are not mixed into the Cloak flow.
    """
    try:
        explicit = str(getattr(driver, "_registration_log_prefix", "") or "").strip()
        if explicit:
            return explicit
        if driver is not None and driver.__class__.__name__ == "CloakSeleniumDriver":
            return "[Cloak registration]"
    except Exception:
        pass
    return "[Roxy registration]"


def _build_driver(opened: RoxyOpenResult):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

    if opened.debugger_address:
        logger.info("[Roxy] Selenium Connect debuggerAddress=%s", opened.debugger_address)
        options = Options()
        # Long-polling / risk-control scripts in the page occasionally make driver.get wait until timeout; eager only waits for DOMContentLoaded.
        options.page_load_strategy = "eager"
        _enable_performance_logging(options)
        options.add_experimental_option("debuggerAddress", opened.debugger_address)
        driver_path = ""
        try:
            raw_data = opened.raw.get("data") if isinstance(opened.raw, dict) else {}
            if isinstance(raw_data, dict):
                driver_path = str(raw_data.get("driver") or raw_data.get("driverPath") or raw_data.get("driver_path") or "").strip()
        except Exception:
            driver_path = ""
        if driver_path:
            logger.info("[Roxy] Using Roxy chromedriver=%s", driver_path)
            driver = webdriver.Chrome(service=Service(executable_path=driver_path), options=options)
        else:
            driver = webdriver.Chrome(options=options)
        _apply_browser_automation_mask(driver)
        return driver

    if opened.webdriver_url:
        logger.info("[Roxy] Selenium Connect webdriver_url=%s", opened.webdriver_url)
        options = Options()
        options.page_load_strategy = "eager"
        _enable_performance_logging(options)
        driver = RemoteWebDriver(command_executor=opened.webdriver_url, options=options)
        _apply_browser_automation_mask(driver)
        return driver

    raise RuntimeError("Roxy did not return a connectable Selenium address")


def _center_browser_window(driver) -> None:
    """Move the visible Roxy window to the center of the Windows primary-screen work area."""
    if bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False)):
        return
    try:
        import platform
        if platform.system().lower() != "windows":
            return
        import ctypes

        class _Rect(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long),
            ]

        work_area = _Rect()
        if not ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(work_area), 0):
            raise OSError("Cannot read the Windows work area")
        size = driver.get_window_size()
        width = max(1, int(size.get("width") or 1))
        height = max(1, int(size.get("height") or 1))
        x = int(work_area.left + max(0, (work_area.right - work_area.left - width) // 2))
        y = int(work_area.top + max(0, (work_area.bottom - work_area.top - height) // 2))
        driver.set_window_position(x, y)
        logger.info("[Roxy] Browser window centered:x=%s y=%s width=%s height=%s", x, y, width, height)
    except Exception as exc:
        logger.warning("[Roxy] Centering the browser window failed, continuing:%s", exc)


def _wait(driver, timeout: int | None = None):
    from selenium.webdriver.support.ui import WebDriverWait
    return WebDriverWait(driver, timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))


def _safe_get(driver, url: str, *, timeout: int = 45, attempts: int = 2, accept_hosts: tuple[str, ...] = ()) -> None:
    """Page navigation with fault tolerance.

    Roxy/Chrome 150 `Timed out receiving message from renderer` occurs occasionally, and the page may actually already be usable.
    After a timeout here we first call `window.stop()` and continue as long as the current URL/DOM has reached the target page; otherwise retry once.
    """
    from selenium.common.exceptions import TimeoutException, WebDriverException

    last_exc: Exception | None = None
    old_timeout = int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)
    hosts = tuple(h.lower() for h in (accept_hosts or ()))
    for attempt in range(1, max(1, attempts) + 1):
        try:
            try:
                driver.set_page_load_timeout(max(10, int(timeout)))
                driver.set_script_timeout(8)
            except Exception:
                pass
            driver.get(url)
            return
        except TimeoutException as exc:
            last_exc = exc
            logger.warning(
                "%s Page load timed out, trying to stop loading and then checking the DOM:url=%s attempt=%s/%s error=%s",
                _log_prefix(driver), url, attempt, attempts, str(exc).splitlines()[0] if str(exc) else "TimeoutException",
            )
            try:
                driver.execute_script("window.stop();")
            except Exception:
                pass
            time.sleep(1.0)
            try:
                current = str(driver.current_url or "").lower()
            except Exception:
                current = ""
            try:
                ready = str(driver.execute_script("return document.readyState || ''") or "")
                has_body = bool(driver.execute_script("return !!document.body"))
            except Exception:
                ready = ""
                has_body = False
            target_ok = any(h in current for h in hosts) if hosts else (url.split("/", 3)[2].lower() in current)
            if target_ok and has_body:
                logger.info(
                    "%s Page load timed out but the DOM is usable, continuing the flow:current=%s readyState=%s",
                    _log_prefix(driver), current[:180], ready or "-",
                )
                return
            if attempt < attempts:
                try:
                    driver.get("about:blank")
                except Exception:
                    pass
                time.sleep(1.5 * attempt)
                continue
        except WebDriverException as exc:
            last_exc = exc
            if attempt < attempts:
                logger.warning("%s Page navigation failed, preparing to retry:url=%s attempt=%s/%s error=%s", _log_prefix(driver), url, attempt, attempts, exc)
                time.sleep(1.5 * attempt)
                continue
            raise
        finally:
            try:
                driver.set_page_load_timeout(old_timeout)
            except Exception:
                pass
    raise last_exc or RuntimeError(f"Page navigation failed: {url}")


def _visible(el) -> bool:
    try:
        return el.is_displayed() and el.is_enabled()
    except Exception:
        return False


def _browser_actions_enabled() -> bool:
    try:
        from config import humanize as _hcfg
        return bool(getattr(_hcfg, "ENABLE_HUMANIZE_BROWSER_ACTIONS", True))
    except Exception:
        return True


def _apply_browser_automation_mask(driver) -> None:
    """After connecting Selenium, reduce the obvious automation traits as far as possible; a failure does not affect the main flow."""
    if not _browser_actions_enabled():
        return
    try:
        script = r"""
        Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => undefined});
        if (!window.chrome) window.chrome = {};
        if (!window.chrome.runtime) window.chrome.runtime = {};
        const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
        if (originalQuery) {
          window.navigator.permissions.query = (parameters) => (
            parameters && parameters.name === 'notifications'
              ? Promise.resolve({ state: Notification.permission })
              : originalQuery(parameters)
          );
        }
        """
        if hasattr(driver, "execute_cdp_cmd"):
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})
        try:
            driver.execute_script(script)
        except Exception:
            pass
        logger.info("%s Injected the script that weakens browser automation traits", _log_prefix(driver))
    except Exception as exc:
        logger.debug("%s Failed to inject the script that weakens automation traits:%s", _log_prefix(driver), exc)


def _human_scroll_to(driver, el) -> None:
    try:
        block = random.choice(["center", "nearest", "center"])
        driver.execute_script("arguments[0].scrollIntoView({block: arguments[1], inline:'nearest'});", el, block)
        if _browser_actions_enabled():
            time.sleep(random.uniform(0.08, 0.35))
            # Slight scroll jitter, so it does not center precisely every time.
            driver.execute_script("window.scrollBy(0, arguments[0]);", random.randint(-90, 90))
            time.sleep(random.uniform(0.05, 0.22))
            driver.execute_script("arguments[0].scrollIntoView({block:'center', inline:'nearest'});", el)
    except Exception:
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        except Exception:
            pass


def _human_click(driver, el, *, label: str = "") -> None:
    """Fast humanized click.

    Using ActionChains used to hang for 1-2 minutes occasionally on Roxy/Chrome 150, making the email submission very slow.
    It now dispatches mouse events through CDP instead; when CDP is unavailable it falls back to JS / native click.
    """
    _human_scroll_to(driver, el)
    if not _browser_actions_enabled():
        time.sleep(0.2)
        el.click()
        return
    try:
        human_delay("click")
        point = driver.execute_script(r"""
        const el = arguments[0];
        const r = el.getBoundingClientRect();
        const x = r.left + r.width * (0.30 + Math.random() * 0.40);
        const y = r.top + r.height * (0.35 + Math.random() * 0.30);
        return {x, y, w:r.width, h:r.height};
        """, el) or {}
        x = float(point.get("x") or 0)
        y = float(point.get("y") or 0)
        if hasattr(driver, "execute_cdp_cmd") and x > 0 and y > 0:
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
            time.sleep(random.uniform(0.05, 0.22))
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1})
            time.sleep(random.uniform(0.035, 0.13))
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1})
        else:
            driver.execute_script(r"""
            const el = arguments[0];
            el.dispatchEvent(new PointerEvent('pointerdown', {bubbles:true, cancelable:true, pointerType:'mouse'}));
            el.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
            el.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
            el.click();
            """, el)
    except Exception as exc:
        logger.debug("%s Humanized click failed, falling back to el.click label=%s err=%s", _log_prefix(driver), label, exc)
        time.sleep(random.uniform(0.12, 0.45))
        try:
            driver.execute_script("arguments[0].click();", el)
        except Exception:
            el.click()


def _human_type_text(driver, el, value: str, *, clear: bool = True) -> None:
    """Type by character / small chunk to trigger real key events; fall back to the JS setter on failure."""
    if not _browser_actions_enabled():
        if clear:
            try:
                el.clear()
            except Exception:
                pass
        el.send_keys(value)
        return
    try:
        _human_scroll_to(driver, el)
        try:
            _human_click(driver, el, label="input_focus")
        except Exception:
            driver.execute_script("arguments[0].focus();", el)
        if clear:
            from selenium.webdriver.common.keys import Keys
            mod = Keys.COMMAND
            try:
                import platform
                if platform.system().lower() != "darwin":
                    mod = Keys.CONTROL
            except Exception:
                pass
            try:
                el.send_keys(mod, "a")
                time.sleep(random.uniform(0.04, 0.16))
                el.send_keys(Keys.BACKSPACE)
            except Exception:
                try:
                    el.clear()
                except Exception:
                    pass
        text = str(value)
        i = 0
        while i < len(text):
            # Email/password are still typed character by character overall, but occasionally two characters at once, for a more natural rhythm.
            step = 2 if random.random() < 0.12 and i + 1 < len(text) else 1
            el.send_keys(text[i:i + step])
            i += step
            human_delay("keystroke")
            if i < len(text) and random.random() < 0.08:
                human_delay("typing_pause")
        driver.execute_script(
            "arguments[0].dispatchEvent(new Event('input', {bubbles:true}));"
            "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));",
            el,
        )
    except Exception as exc:
        logger.debug("%s Humanized typing failed, falling back to JS setter err=%s", _log_prefix(driver), exc)
        _set_element_value(driver, el, value)


def _page_warmup(driver, *, reason: str = "") -> None:
    if not _browser_actions_enabled():
        return
    try:
        human_delay("page_warmup")
        if hasattr(driver, "execute_cdp_cmd"):
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
                "type": "mouseMoved",
                "x": random.randint(80, 360),
                "y": random.randint(80, 260),
            })
    except Exception:
        pass


_MISSING_PAGE_ELEMENT_REFRESH_RETRIES = 3


def _refresh_after_missing_page_element(driver, step: str, retry_index: int) -> bool:
    """Refresh the current page when an element is missing, to avoid misjudging a late page render as a flow failure."""
    max_retries = _MISSING_PAGE_ELEMENT_REFRESH_RETRIES
    if retry_index >= max_retries:
        return False
    try:
        current_url = str(getattr(driver, "current_url", "") or "")
        logger.warning(
            "%s %s not found, refreshing the page and retrying (attempt %s/%s):url=%s",
            _log_prefix(driver), step, retry_index + 1, max_retries, current_url[:180],
        )
        driver.refresh()
        time.sleep(1.5)
        _page_warmup(driver, reason=f"missing_{step}")
        return True
    except Exception as exc:
        logger.warning(
            "%s %s Page refresh after the element went missing failed (attempt %s/%s):%s: %s",
            _log_prefix(driver), step, retry_index + 1, max_retries,
            type(exc).__name__, str(exc)[:180],
        )
        return False


def _find_any(driver, selectors: list[str], timeout: int | None = None):
    from selenium.webdriver.common.by import By

    end = time.time() + (timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))
    last = None
    while time.time() < end:
        for selector in selectors:
            try:
                by = By.XPATH if selector.startswith("//") else By.CSS_SELECTOR
                items = driver.find_elements(by, selector)
                for item in items:
                    if _visible(item):
                        return item
            except Exception as exc:
                last = exc
        time.sleep(0.4)
    raise RuntimeError(f"Page element not found: {selectors}; last={last}")


def _click_any(driver, selectors: list[str], timeout: int | None = None) -> None:
    el = _find_any(driver, selectors, timeout)
    _human_click(driver, el, label="click_any")


def _type_any(driver, selectors: list[str], value: str, timeout: int | None = None, clear: bool = True) -> None:
    el = _find_any(driver, selectors, timeout)
    _human_type_text(driver, el, value, clear=clear)


_EMAIL_INPUT_SELECTORS = [
    "input[type='email']",
    "input[name='email']",
    "input[name='username']",
    "input#email-input",
    "input[autocomplete='email']",
]


class _EmailFlowAdvanced(RuntimeError):
    """While waiting for the email input box, the page has actually already moved on to the following authentication steps."""

    def __init__(self, state: str):
        super().__init__(state)
        self.state = state


def _current_email_submit_next_state(driver) -> str | None:
    """Recognize the valid state after the email submit without waiting, to avoid misjudging a slow redirect as a lost email page."""
    if _has_access_token(driver):
        return "logged_in"
    if _is_login_password_page(driver):
        return "login_password"
    if _is_email_verification_page(driver):
        return "otp"
    if _is_signup_password_page(driver):
        return "password"
    return None


def _email_entry_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled;
        const attrText = el => [
          el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
          el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
          el.getAttribute('data-auth-provider'), el.getAttribute('href'), el.getAttribute('action'),
          el.getAttribute('formaction'), el.getAttribute('value')
        ].filter(Boolean).join(' ').toLowerCase();
        const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', value: el.value || ''
        })).slice(0, 30);
        const actions = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')]
          .filter(visible).map(el => ({tag: el.tagName, type: el.getAttribute('type') || '', attrs: attrText(el)})).slice(0, 40);
        return {url: location.href, title: document.title, inputs, actions};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _find_visible_email_input_js(driver):
    return driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly;
    const selectors = [
      'input[type="email"]',
      'input[name="email"]',
      'input[name="username"]',
      'input#email-input',
      'input[autocomplete="email"]'
    ];
    for (const sel of selectors) {
      const el = [...document.querySelectorAll(sel)].find(visible);
      if (el) return el;
    }
    return null;
    """)


def _is_oauth_consent_like(driver) -> bool:
    """Detect whether we have reached the OAuth authorization / consent page. No email branch or global submit button may be clicked any more here."""
    try:
        return bool(driver.execute_script(r"""
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
        """))
    except Exception:
        return False


def _is_external_idp_url(url: str) -> bool:
    u = str(url or '').lower()
    return any(x in u for x in (
        'accounts.google.', 'google.com/o/oauth', 'appleid.apple.', 'login.microsoftonline.',
        'login.live.', 'github.com/login/oauth', 'facebook.com/', 'saml', 'sso'
    ))


def _assert_not_external_idp(driver, label: str = '') -> None:
    try:
        current = str(driver.current_url or '')
    except Exception:
        current = ''
    if _is_external_idp_url(current):
        raise RuntimeError(f"Entered a third-party account authorization page by mistake ({label}):{current}")


def _click_email_entry_option(driver) -> bool:
    """Click the 'email method' entry; only look at DOM technical attributes, not at the visible button wording, and explicitly exclude third parties such as Google."""
    if _is_oauth_consent_like(driver):
        logger.info("%s The current page looks like an OAuth authorization page, skipping the email entry fallback click", _log_prefix(driver))
        return False
    target = driver.execute_script(r"""
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
    const candidates = [...document.querySelectorAll('button,a,[role="button"],input[type="button"],input[type="submit"]')]
      .filter(visible)
      .map(el => ({el, attrs: attrText(el), hasLogo: !!el.querySelector('img,svg,use')}))
      .filter(x => good.test(x.attrs) && !bad.test(x.attrs) && !x.hasLogo);
    if (candidates.length !== 1) return null;
    candidates[0].el.scrollIntoView({block:'center'});
    return candidates[0].el;
    """)
    if target:
        _human_click(driver, target, label="email_entry")
        return True
    return False


def _wait_for_email_input(driver, timeout: int | None = None):
    """Enter the email login/registration method and return the visible email input box that was found."""
    wait_timeout = timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT)
    last_state = None
    for refresh_retry in range(_MISSING_PAGE_ELEMENT_REFRESH_RETRIES + 1):
        end = time.time() + wait_timeout
        clicked_email_option = False
        while time.time() < end:
            advanced = _current_email_submit_next_state(driver)
            if advanced:
                raise _EmailFlowAdvanced(advanced)
            el = _find_visible_email_input_js(driver)
            if el:
                return el
            last_state = _email_entry_state(driver)
            if not clicked_email_option and _click_email_entry_option(driver):
                clicked_email_option = True
                time.sleep(1.0)
                _assert_not_external_idp(driver, "after clicking the email entry")
                continue
            time.sleep(0.4)
        if not _refresh_after_missing_page_element(driver, "email input box / email entry", refresh_retry):
            break
    raise RuntimeError(
        f"Email input box / email entry not found, refreshed and retried {_MISSING_PAGE_ELEMENT_REFRESH_RETRIES} times"
        f"(text recognition was not used),state={last_state}"
    )


def _type_email_address(driver, email: str, timeout: int | None = None) -> None:
    """Enter the email login/registration method and fill in the email. The whole process does not depend on visible page text."""
    el = _wait_for_email_input(driver, timeout=timeout)
    _human_type_text(driver, el, email, clear=True)


def _submit_nearest_form_for_active_input(driver) -> bool:
    if _is_oauth_consent_like(driver):
        logger.info("%s The current page looks like an OAuth authorization page, email submission is forbidden", _log_prefix(driver))
        return False
    result = driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
    const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete="email"]')]
      .find(visible);
    if (!input) return {ok:false, reason:'missing_email_input'};
    const value = String(input.value || '').trim();
    if (!value || !value.includes('@')) return {ok:false, reason:'email_value_not_ready', value};
    const form = input.closest('form');
    if (!form) return {ok:false, reason:'missing_form'};

    const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|sso|saml|idp|provider|authorize|consent|grant|allow/;
    const attrText = el => {
      const own = [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
        el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'),
        el.getAttribute('aria-label'), el.getAttribute('href'), el.getAttribute('formaction'), el.value, el.className]
        .filter(Boolean).join(' ');
      const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
        .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
          x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
          .filter(Boolean).join(' '))
        .join(' ');
      return `${own} ${desc}`.toLowerCase();
    };
    const inputRect = input.getBoundingClientRect();
    const formId = form.getAttribute('id') || '';
    const scopedButtons = [
      ...form.querySelectorAll('button,input[type="submit"]'),
      ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])
    ].filter((el, idx, arr) => arr.indexOf(el) === idx);
    const rawButtons = scopedButtons
      .filter(visible)
      .map((el, idx) => {
        const r = el.getBoundingClientRect();
        const attrs = attrText(el);
        const hasLogo = !!el.querySelector('img,svg,use');
        const isBad = bad.test(attrs) || hasLogo;
        const belowInput = r.top >= inputRect.bottom - 10;
        const distance = Math.max(0, r.top - inputRect.bottom) + Math.abs((r.left + r.right) / 2 - (inputRect.left + inputRect.right) / 2) / 10;
        const cls = String(el.className || '').toLowerCase();
        const type = String(el.getAttribute('type') || '').toLowerCase();
        // ChatGPT The main button of the new email page looks like:
        // <button class="... btn-primary ... w-full ..." type="submit"><div>Continue</div></button>
        // Prefer the primary submit under the same form, instead of misjudging ambiguity because several buttons are at a similar distance.
        const isPrimarySubmit = (el.tagName === 'BUTTON' || el.tagName === 'INPUT') && type === 'submit'
          && (/\bbtn-primary\b/.test(cls) || /\b_primary_/.test(cls) || /\bw-full\b/.test(cls));
        const score = (isPrimarySubmit ? 1000 : 0) + (type === 'submit' ? 100 : 0) - distance;
        return {el, idx, attrs, isBad, hasLogo, belowInput, distance, score, isPrimarySubmit, tag: el.tagName, type};
      });
    const safe = rawButtons.filter(x => !x.isBad && x.belowInput)
      .sort((a,b) => b.score - a.score || a.distance - b.distance || a.idx - b.idx);
    if (!safe.length) {
      return {ok:false, reason:'no_safe_submit', buttons: rawButtons.map(x => ({idx:x.idx, isBad:x.isBad, hasLogo:x.hasLogo, belowInput:x.belowInput, primary:x.isPrimarySubmit, attrs:x.attrs.slice(0,160), type:x.type}))};
    }
    // With several safe buttons, the page is only considered ambiguous when there is no clear primary submit and the distances are close.
    if (!safe[0].isPrimarySubmit && safe.length > 1 && Math.abs(safe[0].distance - safe[1].distance) < 8) {
      return {ok:false, reason:'ambiguous_submit', buttons: safe.slice(0,3).map(x => ({idx:x.idx, distance:x.distance, score:x.score, primary:x.isPrimarySubmit, attrs:x.attrs.slice(0,160), type:x.type}))};
    }
    const target = safe[0].el;
    target.scrollIntoView({block:'center'});
    window.__roxy_email_submit_debug = {at: Date.now(), targetAttrs: safe[0].attrs.slice(0,240), buttonCount: rawButtons.length, primary:safe[0].isPrimarySubmit};
    return {ok:true, reason:safe[0].isPrimarySubmit ? 'primary_submit' : 'safe_submit', target, targetAttrs:safe[0].attrs.slice(0,160), primary:safe[0].isPrimarySubmit};
    """) or {}
    if result.get("ok"):
        target = result.get("target")
        if target:
            _human_click(driver, target, label="email_submit")
        else:
            logger.warning("%s The email submit did not return the target element, falling back to requestSubmit", _log_prefix(driver))
            driver.execute_script("document.querySelector('form')?.requestSubmit?.();")
        logger.info("%s Email form safe submit:%s", _log_prefix(driver), result)
        time.sleep(0.8)
        _assert_not_external_idp(driver, "after submitting the email")
        return True
    logger.warning("%s Email submission not executed:%s", _log_prefix(driver), result)
    return False


def _current_email_input_value(driver) -> str:
    try:
        state = _email_input_value_state(driver)
        for item in state.get("inputs") or []:
            value = str(item.get("value") or "").strip()
            if "@" in value:
                return value
    except Exception:
        pass
    return ""


def _stabilize_email_input_before_submit(driver, email: str) -> dict:
    """Before submitting, stabilize the DOM value / React controlled state / blur-change state."""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_email_input'};

        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.scrollIntoView({block:'center', inline:'nearest'});
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;

        // Let React / form validation receive the complete input chain as far as possible.
        try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true, inputType:'insertText', data:email})); } catch (_) {}
        try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email})); } catch (_) {
          input.dispatchEvent(new Event('input', {bubbles:true}));
        }
        input.dispatchEvent(new Event('change', {bubbles:true}));
        input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
        input.blur();
        input.focus();

        const form = input.closest('form');
        const submit = form?.querySelector('button[type="submit"],input[type="submit"]');
        return {
          ok:true,
          value: input.value,
          active: document.activeElement === input,
          hasForm: !!form,
          hasSubmit: !!submit,
          submitDisabled: submit ? (!!submit.disabled || String(submit.getAttribute('aria-disabled') || '').toLowerCase() === 'true') : null,
          url: location.href
        };
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _submit_email_form_stable(driver, email: str) -> dict:
    """The first submit already runs the way a 'resubmit succeeded' would: after the value is stable, Enter + DOM click."""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
        const editable = el => visible(el) && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .find(editable);
        if (!input) return {ok:false, reason:'missing_email_input'};
        if (!email || !email.includes('@')) return {ok:false, reason:'empty_email', value: email};

        const form = input.closest('form');
        if (!form) return {ok:false, reason:'missing_form'};

        const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
        const attrText = el => {
          const own = [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
            el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'),
            el.getAttribute('aria-label'), el.getAttribute('href'), el.getAttribute('formaction'), el.value, el.className]
            .filter(Boolean).join(' ');
          const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
            .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
              x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
              .filter(Boolean).join(' '))
            .join(' ');
          return `${own} ${desc}`.toLowerCase();
        };

        const formId = form.getAttribute('id') || '';
        const buttons = [
          ...form.querySelectorAll('button,input[type="submit"]'),
          ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])
        ].filter((el, idx, arr) => arr.indexOf(el) === idx)
          .filter(el => visible(el) && !bad.test(attrText(el)) && !el.querySelector('img,svg,use'));
        const submit = buttons.find(el => (el.getAttribute('type') || '').toLowerCase() === 'submit') || buttons[0] || null;
        if (!submit) return {ok:false, reason:'missing_safe_submit'};

        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.scrollIntoView({block:'center', inline:'nearest'});
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;
        try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true, inputType:'insertText', data:email})); } catch (_) {}
        try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email})); } catch (_) {
          input.dispatchEvent(new Event('input', {bubbles:true}));
        }
        input.dispatchEvent(new Event('change', {bubbles:true}));
        input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
        input.blur();
        input.focus();

        submit.scrollIntoView({block:'center', inline:'nearest'});

        // Do not run submit.click() synchronously inside execute_script:
        // ChromeDriver it waits for the front-end submit/navigation, and on Roxy/Chrome 150 it may hang until the page/script timeout.
        // setTimeout Let Selenium return first, and the click happens asynchronously in the page event loop, consistent with the resubmit logic.
        setTimeout(() => {
          try {
            input.focus();
            input.dispatchEvent(new KeyboardEvent('keydown', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            input.dispatchEvent(new KeyboardEvent('keypress', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            input.dispatchEvent(new KeyboardEvent('keyup', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            if (submit && !submit.disabled) submit.click();
            else if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
          } catch (_) {}
        }, 80);

        window.__roxy_email_submit_debug = {
          at: Date.now(),
          mode: 'stable_async_enter_click',
          value: input.value,
          submitAttrs: attrText(submit).slice(0, 240)
        };
        return {
          ok:true,
          reason:'stable_async_enter_click',
          value: input.value,
          submitDisabled: !!submit.disabled || String(submit.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
          submitAttrs: attrText(submit).slice(0, 180),
          url: location.href
        };
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _submit_email_step(driver, email: str | None = None) -> None:
    # No longer prefer the in-browser NextAuth fetch:
    # Roxy/Chrome 150 execute_async_script + fetch occasionally hangs until the script timeout;
    # in practice, if the first UI submit stays at /auth/login?email=..., resubmitting the form via _recover_email_submit_if_stuck is more stable.
    email_value = str(email or _current_email_input_value(driver) or "").strip()
    stable = _stabilize_email_input_before_submit(driver, email_value)
    logger.info("%s State stable before the email submit:%s", _log_prefix(driver), stable)
    time.sleep(random.uniform(0.8, 1.8) if _browser_actions_enabled() else 0.4)

    stable_submit = _submit_email_form_stable(driver, email_value)
    if stable_submit.get("ok"):
        logger.info("%s Email stable form submit:%s", _log_prefix(driver), stable_submit)
        time.sleep(1.0)
        _assert_not_external_idp(driver, "after submitting the email via the stable form")
        return
    logger.warning("%s Email stable form submit failed, falling back to the UI click submit:%s", _log_prefix(driver), stable_submit)
    if _submit_nearest_form_for_active_input(driver):
        return
    raise RuntimeError(f"Cannot submit the email step (refusing to fall back on page text or the first submit, to avoid clicking a third-party login by mistake),state={_email_entry_state(driver)}")


def _recover_email_submit_if_stuck(driver, email: str) -> dict:
    """When the email submit stays at /auth/login?email= and the input box is cleared, do one more native form submit."""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_email_input'};
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;
        input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email}));
        input.dispatchEvent(new Event('change', {bubbles:true}));
        const form = input.closest('form');
        const submit = form?.querySelector('button[type="submit"],input[type="submit"]');
        setTimeout(() => {
          try {
            input.dispatchEvent(new KeyboardEvent('keydown', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            input.dispatchEvent(new KeyboardEvent('keyup', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            if (submit && !submit.disabled) submit.click();
            else if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
          } catch (_) {}
        }, 80);
        return {ok:true, reason:'resubmitted_email_form', value: input.value, hasForm: !!form, hasSubmit: !!submit};
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _submit_email_via_browser_nextauth(driver, email: str) -> dict:
    """Call ChatGPT NextAuth signin inside the Roxy browser context.

    UI submit On Roxy/Chrome 150 it occasionally only jumps to `/auth/login?email=...` and then stalls.
    Here we switch to an in-page fetch of the browser, still using the cookie / fingerprint environment of the current Roxy browser,
    and let the browser navigate after the auth.openai.com authorize URL is obtained.
    """
    try:
        current = str(getattr(driver, "current_url", "") or "")
        if "chatgpt.com" not in current:
            return {"ok": False, "reason": "not_on_chatgpt", "url": current[:180]}
    except Exception:
        current = ""

    did = str(uuid.uuid4())
    auth_log_id = str(uuid.uuid4())
    old_script_timeout = int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)
    try:
        try:
            driver.set_script_timeout(25)
        except Exception:
            pass
        result = driver.execute_async_script(r"""
        const email = String(arguments[0] || '').trim();
        const did = String(arguments[1] || '');
        const authLogId = String(arguments[2] || '');
        const done = arguments[arguments.length - 1];
        (async () => {
          try {
            const csrfResp = await fetch('/api/auth/csrf', {
              method: 'GET',
              credentials: 'include',
              headers: {
                'accept': 'application/json',
                'cache-control': 'no-cache',
                'pragma': 'no-cache'
              }
            });
            const csrfText = await csrfResp.text();
            let csrfData = {};
            try { csrfData = JSON.parse(csrfText); } catch (_) {}
            const csrfToken = csrfData.csrfToken || '';
            if (!csrfResp.ok || !csrfToken) {
              done({ok:false, stage:'csrf', status:csrfResp.status, body:csrfText.slice(0, 500)});
              return;
            }

            const q = new URLSearchParams({
              prompt: 'login',
              'ext-oai-did': did,
              auth_session_logging_id: authLogId,
              'ext-passkey-client-capabilities': '11111',
              screen_hint: 'login_or_signup',
              login_hint: email
            });
            const body = new URLSearchParams({
              callbackUrl: 'https://chatgpt.com/',
              csrfToken,
              json: 'true'
            });
            const resp = await fetch('/api/auth/signin/openai?' + q.toString(), {
              method: 'POST',
              credentials: 'include',
              headers: {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'cache-control': 'no-cache',
                'pragma': 'no-cache'
              },
              body: body.toString()
            });
            const text = await resp.text();
            let data = {};
            try { data = JSON.parse(text); } catch (_) {}
            let url = data.url || '';
            if (!resp.ok || !url) {
              done({ok:false, stage:'signin', status:resp.status, body:text.slice(0, 700)});
              return;
            }

            try {
              const u = new URL(url, location.href);
              if (!u.searchParams.get('screen_hint')) u.searchParams.set('screen_hint', 'login_or_signup');
              if (!u.searchParams.get('login_hint')) u.searchParams.set('login_hint', email);
              if (!u.searchParams.get('ext-oai-did')) u.searchParams.set('ext-oai-did', did);
              if (!u.searchParams.get('auth_session_logging_id')) u.searchParams.set('auth_session_logging_id', authLogId);
              url = u.toString();
            } catch (_) {}
            window.location.assign(url);
            done({ok:true, stage:'redirect', url:url.slice(0, 260)});
          } catch (e) {
            done({ok:false, stage:'exception', error:String(e && (e.stack || e.message) || e).slice(0, 700)});
          }
        })();
        """, email, did, auth_log_id) or {}
        return result if isinstance(result, dict) else {"ok": False, "reason": "invalid_result", "result": str(result)[:300]}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    finally:
        try:
            driver.set_script_timeout(old_script_timeout)
        except Exception:
            pass


def _email_input_value_state(driver) -> dict:
    """Read the state of the currently visible email box, to confirm after the submit whether we really entered the next step."""
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const inputs = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .filter(visible)
          .map(el => ({type: el.getAttribute('type') || '', name: el.name || '', id: el.id || '', autocomplete: el.getAttribute('autocomplete') || '', value: el.value || ''}));
        return {url: location.href, inputs};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _is_email_login_page_still_present(driver) -> bool:
    state = _email_input_value_state(driver)
    return bool(state.get("inputs"))


def _wait_email_submit_next_state(driver, email: str, timeout: int = 18) -> str:
    """After the email submit wait to enter password / otp / logged_in; if still on the email page return email_page.

    Cloak/Playwright On this path, after clicking submit the page often goes through an SPA navigation first:
    `chatgpt.com/auth/login?email=...`, and React briefly clears the email input at the same time.
    The old logic returned `email_cleared` immediately upon seeing an empty input, which led to refilling too early before really jumping to
    `auth.openai.com/...` , forming a "submit -> clear -> refill" loop.
    Here email_cleared is debounced: only record it and keep observing for a few seconds; if during that time it enters
    password/otp/login_password/logged_in then return the real state, and only let the upper layer retry when it keeps being cleared.
    """
    end = time.time() + timeout
    last = None
    cleared_seen_at: float | None = None
    cleared_last_log_at = 0.0
    cleared_recover_done = False
    expected_email = str(email or "").strip().lower()
    while time.time() < end:
        advanced = _current_email_submit_next_state(driver)
        if advanced:
            return advanced
        state = _email_input_value_state(driver)
        last = state
        inputs = state.get("inputs") or []
        if inputs:
            values = [str(i.get("value") or "") for i in inputs]
            url = str(state.get("url") or "")
            has_blank = any(v == "" for v in values)
            has_expected = any(v.strip().lower() == expected_email for v in values)
            if has_blank and not has_expected:
                now = time.time()
                if cleared_seen_at is None:
                    cleared_seen_at = now
                # URL With the email query parameter present it looks more like an intermediate state after the submit, so it gets a longer observation window.
                debounce = 18.0 if ("/auth/login" in url and "email=" in url) else 5.0
                if now - cleared_last_log_at > 2.0:
                    logger.info(
                        "%s After the email submit the input box was detected to be briefly cleared, continuing to wait for the jump:elapsed=%.1fs debounce=%.1fs url=%s",
                        _log_prefix(driver), now - cleared_seen_at, debounce, url[:180],
                    )
                    cleared_last_log_at = now
                if (
                    not cleared_recover_done
                    and "/auth/login" in url
                    and "email=" in url
                    and now - cleared_seen_at >= 2.0
                ):
                    recover = _recover_email_submit_if_stuck(driver, email)
                    cleared_recover_done = True
                    logger.info("%s After the email submit it still stays at login?email, resubmitting the form midway:%s", _log_prefix(driver), recover)
                if now - cleared_seen_at >= debounce:
                    return "email_cleared"
            else:
                cleared_seen_at = None
            # Still the current email page, keep waiting briefly.
        time.sleep(0.8)
    logger.info("%s Timed out waiting for the next step after the email submit, last email page state=%s", _log_prefix(driver), last)
    return "email_page" if _is_email_login_page_still_present(driver) else "unknown"


def _submit_email_and_wait_next(
    driver,
    email: str | None,
    attempts: int = 3,
    email_supplier: Callable[[], str] | None = None,
) -> str:
    """Fill in and submit the email; return only after confirming entry into password/otp/logged_in."""
    last_state = None
    current_email = str(email or "").strip()
    for attempt in range(1, attempts + 1):
        advanced = _current_email_submit_next_state(driver)
        if advanced:
            if advanced == "login_password":
                raise RuntimeError(f"After submitting the email it entered the login password page; treated as a registered/unusable email and deactivated: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}")
            logger.info("%s Before retrying to fill the email the page was found to have entered the next step already:%s", _log_prefix(driver), advanced)
            return advanced
        try:
            if current_email:
                _type_email_address(driver, current_email, timeout=20)
            else:
                # First confirm the page has a usable input box, then claim the email; the claim must not happen before the page navigation.
                email_input = _wait_for_email_input(driver, timeout=20)
                if email_supplier is None:
                    raise RuntimeError("An email input box was found, but no email allocator was provided")
                current_email = str(email_supplier() or "").strip()
                if not current_email:
                    raise RuntimeError("The email allocator returned an empty email address")
                _human_type_text(driver, email_input, current_email, clear=True)
        except _EmailFlowAdvanced as exc:
            if exc.state == "login_password":
                raise RuntimeError(f"After submitting the email it entered the login password page; treated as a registered/unusable email and deactivated: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}") from exc
            logger.info("%s While waiting for the email input box the page entered the next step:%s", _log_prefix(driver), exc.state)
            return exc.state
        state = _email_input_value_state(driver)
        last_state = state
        values = [str(i.get("value") or "") for i in (state.get("inputs") or [])]
        if not any(v.strip().lower() == current_email.lower() for v in values):
            logger.warning("%s Email write verification failed, preparing to retry:attempt=%s/%s state=%s", _log_prefix(driver), attempt, attempts, state)
            time.sleep(0.8)
            continue
        logger.info("%s Filled in the email and verification passed:%s", _log_prefix(driver), current_email)
        human_delay("form")
        _submit_email_step(driver, current_email)
        logger.info("%s Email submitted, waiting to enter the password page or the verification code page (%s/%s)", _log_prefix(driver), attempt, attempts)
        state_name = _wait_email_submit_next_state(driver, current_email, timeout=20)
        if state_name == "login_password":
            raise RuntimeError(f"After submitting the email it entered the login password page; treated as a registered/unusable email and deactivated: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}")
        if state_name in ("password", "otp", "logged_in"):
            logger.info("%s After the email submit it entered the next step:%s", _log_prefix(driver), state_name)
            return state_name
        diagnostic_state = _email_input_value_state(driver)
        # Selenium While reading the DOM the page may just have finished a slow redirect. After the diagnostic sampling it must be judged once more,
        # otherwise the "refill the email" branch would be entered wrongly when the verification code input box has already appeared.
        advanced = _current_email_submit_next_state(driver)
        if advanced:
            if advanced == "login_password":
                raise RuntimeError(f"After submitting the email it entered the login password page; treated as a registered/unusable email and deactivated: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}")
            logger.info("%s During the email submit diagnostics the page entered the next step:%s", _log_prefix(driver), advanced)
            return advanced
        logger.warning("%s After the email submit it still did not enter the next step: %s, preparing to refill and retry state=%s", _log_prefix(driver), state_name, diagnostic_state)
        time.sleep(1.0)
    raise RuntimeError(f"After the email submit it did not enter the password page / verification code page, last state={last_state}")


def _type_otp(driver, code: str) -> None:
    from selenium.webdriver.common.by import By

    for refresh_retry in range(_MISSING_PAGE_ELEMENT_REFRESH_RETRIES + 1):
        # single input box
        for selector in [
            "input[autocomplete='one-time-code']",
            "input[name='code']",
            "input[inputmode='numeric']",
            "input[type='tel']",
        ]:
            els = [e for e in driver.find_elements(By.CSS_SELECTOR, selector) if _visible(e)]
            if len(els) == 1:
                _human_type_text(driver, els[0], code, clear=True)
                return

        # 6 split input boxes
        boxes = [e for e in driver.find_elements(By.CSS_SELECTOR, "input") if _visible(e)]
        numeric_boxes = []
        for e in boxes:
            attrs = " ".join(str(e.get_attribute(k) or "") for k in ("inputmode", "autocomplete", "aria-label", "name", "id", "type"))
            if any(x in attrs.lower() for x in ("numeric", "one-time", "code", "otp", "tel")):
                numeric_boxes.append(e)
        if len(numeric_boxes) >= len(code):
            for e, ch in zip(numeric_boxes, code):
                if _browser_actions_enabled():
                    _human_scroll_to(driver, e)
                    time.sleep(random.uniform(0.04, 0.18))
                e.send_keys(ch)
                if _browser_actions_enabled():
                    human_delay("keystroke")
            return

        if not _refresh_after_missing_page_element(driver, "OTP input box", refresh_retry):
            break

    raise RuntimeError(
        f"OTP input box not found, refreshed and retried {_MISSING_PAGE_ELEMENT_REFRESH_RETRIES} times"
    )


def _email_otp_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', inputmode: el.getAttribute('inputmode') || '',
          ariaInvalid: el.getAttribute('aria-invalid') || '', value: el.value || ''
        }));
        const buttons = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')].filter(visible).map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', value: el.getAttribute('value') || '',
          action: el.getAttribute('data-dd-action-name') || '', aria: el.getAttribute('aria-label') || '',
          disabled: !!el.disabled || String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
          text: (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 120)
        }));
        const errors = [...document.querySelectorAll('.react-aria-FieldError,[slot="errorMessage"],[id$="-error"],[aria-invalid="true"] + *,[class*="error"]')]
          .filter(visible).map(el => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean);
        return {url: location.href, title: document.title, inputs, buttons, errors, text: (document.body?.innerText || '').slice(0, 1200)};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, 'current_url', ''), "error": f"{type(exc).__name__}: {exc}"}


def _is_email_verification_page(driver) -> bool:
    try:
        url = str(driver.current_url or '').lower()
    except Exception:
        url = ''
    if '/log-in/password' in url:
        return False
    if 'email-verification' in url:
        return True
    state = _email_otp_page_state(driver)
    attrs = ' '.join(' '.join(str(i.get(k) or '') for k in ('type','name','id','autocomplete','inputmode')) for i in (state.get('inputs') or [])).lower()
    return 'one-time-code' in attrs or 'otp' in attrs or 'code' in attrs


def _clear_otp_inputs(driver) -> None:
    try:
        driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const inputs = [...document.querySelectorAll('input')].filter(visible).filter(el => {
          const attrs = [el.type, el.name, el.id, el.autocomplete, el.inputMode, el.getAttribute('aria-label')].join(' ').toLowerCase();
          return /one-time|otp|code|numeric|tel/.test(attrs);
        });
        for (const el of inputs) {
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (setter) setter.call(el, ''); else el.value = '';
          el.dispatchEvent(new Event('input', {bubbles:true}));
          el.dispatchEvent(new Event('change', {bubbles:true}));
        }
        """)
    except Exception:
        pass


def _click_resend_email_otp(driver, timeout: int = 20) -> dict:
    """Click to resend the email verification code. Prefer recognition by DOM attributes, text only as a fallback."""
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            btn = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
            const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const candidates = [...document.querySelectorAll('button,a,[role=button],[role=link],input[type=button],input[type=submit]')].filter(visible);
            const attrHit = candidates.find(el => {
              if (!enabled(el)) return false;
              const attrs = [el.id, el.getAttribute('name'), el.getAttribute('value'), el.getAttribute('data-dd-action-name'), el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid')]
                .join(' ').toLowerCase();
              const name = String(el.getAttribute('name') || '').toLowerCase();
              const value = String(el.getAttribute('value') || '').toLowerCase();
              if (name === 'intent' && value === 'resend') return true;
              return /resend|send.*new|new.*code|again/.test(attrs);
            });
            if (attrHit) return attrHit;
            // Fallback: multilingual text, to avoid getting stuck when the page has no stable attributes.
            return candidates.find(el => enabled(el) && /resend|send\s+(?:a\s+)?new\s+code|send\s+again|重新发送|重新发送电子邮件|重发|再次发送|再送信|新しい|届かない/.test((el.innerText || el.textContent || '').toLowerCase())) || null;
            """)
            if btn:
                text = str(btn.text or btn.get_attribute('value') or btn.get_attribute('data-dd-action-name') or '').strip()
                _human_click(driver, btn, label="resend_otp")
                logger.info("%s[OTP] Clicked the resend verification code button:%s", _log_prefix(driver), text or '-')
                time.sleep(random.uniform(1.1, 2.4) if _browser_actions_enabled() else 1.5)
                return {"ok": True, "text": text}
        except Exception as exc:
            last = exc
        time.sleep(0.5)
    raise RuntimeError(f"No clickable resend verification code button found: last={last}, state={_email_otp_page_state(driver)}")


def _wait_after_email_otp_submit(driver, timeout: int = 30) -> str:
    """After the OTP is submitted, wait for the page to leave the verification code page.

    It is only judged invalid when the page clearly shows a verification code error (aria-invalid / error wording);
    when the network is slow the page redirect may take more than 10s, and after a timeout, as long as there is no error marker, it is handled as accepted,
    to avoid misjudging an already successfully submitted code as failed and wrongly clicking "resend", which would mess up the flow.
    """
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        time.sleep(0.5)
        if not _is_email_verification_page(driver):
            return 'accepted'
        last = _email_otp_page_state(driver)
        invalid = any(str(i.get('ariaInvalid') or '').lower() == 'true' for i in (last.get('inputs') or []))
        if invalid or (last.get('errors') or []):
            return 'invalid'
    if _is_email_verification_page(driver):
        # Still staying after the timeout: if there is no clear error marker, judge it as submitted successfully with a slow redirect, and let it pass as accepted.
        has_error_mark = bool(last.get('errors')) or any(
            str(i.get('ariaInvalid') or '').lower() == 'true' for i in (last.get('inputs') or [])
        )
        if has_error_mark:
            logger.warning("%s[OTP] After the submit it still stays on the verification code page and an error marker exists, handled as an invalid verification code snapshot=%s", _log_prefix(driver), last)
            return 'invalid'
        logger.warning(
            "%s[OTP] %ss after the submit it is still on the verification code page but without an error marker, handled as a slow redirect (accepted) snapshot=%s",
            _log_prefix(driver), timeout, last
        )
        return 'accepted'
    return 'accepted'


def _click_continue(driver) -> None:
    _click_any(driver, [
        "button[type='submit']",
        "//button[@data-dd-action-name='Continue']",
        "//button[@data-dd-action-name='continue']",
        "//button[@data-login-web-auth-control='true' and @type='submit']",
        "//button[contains(., 'Continue')]",
        "//button[contains(., '続行')]",
        "//button[contains(., '继续')]",
        "//button[contains(., 'Sign up')]",
        "//button[contains(., 'Create')]",
        "//button[contains(., 'Next')]",
    ], timeout=20)


def _maybe_accept(driver) -> None:
    # Only handle clear cookie/consent overlay buttons; do not use "Continue" as a fallback,
    # because with a non-Japan exit "Continue with Google" would also match, causing a wrong click on Google login.
    for selectors in ([
        "button#onetrust-accept-btn-handler",
        "button[data-testid='cookie-accept']",
        "button[data-testid='accept-cookies']",
        "//button[contains(., 'Accept')]",
        "//button[contains(., '同意')]",
        "//button[contains(., 'Agree')]",
    ],):
        try:
            _click_any(driver, selectors, timeout=3)
            time.sleep(0.5)
        except Exception:
            pass


def _page_snapshot(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const inputs = [...document.querySelectorAll('input,select,textarea')].map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
          id: el.id || '', placeholder: el.getAttribute('placeholder') || '',
          autocomplete: el.getAttribute('autocomplete') || '', aria: el.getAttribute('aria-label') || '',
          value: el.value || '', visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).filter(x => x.visible).slice(0, 30);
        const buttons = [...document.querySelectorAll('button,a[role=button],input[type=submit]')].map(el => ({
          text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(),
          type: el.getAttribute('type') || '', visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
          disabled: !!el.disabled
        })).filter(x => x.visible).slice(0, 30);
        const widgets = [...document.querySelectorAll('[role=spinbutton], .react-aria-Select, [data-testid="hidden-select-container"] select')].map(el => ({
          tag: el.tagName, role: el.getAttribute('role') || '', dataType: el.getAttribute('data-type') || '',
          aria: el.getAttribute('aria-label') || '', text: (el.innerText || el.textContent || '').trim().slice(0, 80),
          visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).slice(0, 30);
        return {url: location.href, title: document.title, text: (document.body?.innerText || '').slice(0, 2000), inputs, buttons, widgets};
        """) or {}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "url": getattr(driver, 'current_url', '')}


def _has_access_token(driver) -> bool:
    try:
        result = driver.execute_async_script(r"""
        const done = arguments[0];
        fetch('https://chatgpt.com/api/auth/session', {credentials:'include'})
          .then(r => r.json()).then(j => done(Boolean(j && j.accessToken)))
          .catch(() => done(false));
        """)
        return bool(result)
    except Exception:
        return False


def _is_profile_like(snapshot: dict) -> bool:
    """Profile page recognition: compatible with about-you/profile; the age/birthday controls may not be inputs but React Aria widgets."""
    url = str(snapshot.get('url') or '').lower()
    inputs = snapshot.get('inputs') or []
    widgets = snapshot.get('widgets') or []
    attrs = ' '.join(
        ' '.join(str(i.get(k) or '') for k in ('name', 'id', 'placeholder', 'autocomplete', 'aria', 'type')).lower()
        for i in inputs
    )
    widget_attrs = ' '.join(
        ' '.join(str(i.get(k) or '') for k in ('role', 'dataType', 'aria', 'text', 'tag')).lower()
        for i in widgets
    )
    has_profile_url = any(x in url for x in ('about-you', 'profile', 'signup/profile', 'create-account/profile'))
    has_name_field = (
        'autocomplete name' in attrs
        or ' name ' in f' {attrs} '
        or 'fullname' in attrs
        or 'full_name' in attrs
        or 'firstname' in attrs
        or 'lastname' in attrs
    )
    has_age_or_birth_field = any(x in f' {attrs} {widget_attrs} ' for x in (
        ' age', '-age', '_age', 'birth', 'birthday', 'birthdate',
        ' month', '-month', '_month', 'data-type month',
        ' day', '-day', '_day', 'data-type day',
        ' year', '-year', '_year', 'data-type year',
        'spinbutton', 'react-aria-select', 'type number',
    ))
    # about-you/profile URL itself is already strong enough; some new pages use React Aria controls without a name.
    return has_profile_url and (has_name_field or has_age_or_birth_field or bool(inputs) or bool(widgets))


def _set_element_value(driver, el, value: str) -> None:
    """Compatible with React controlled inputs: set the value with the native setter and dispatch input/change."""
    driver.execute_script(r"""
    const el = arguments[0];
    const value = String(arguments[1]);
    const tag = (el.tagName || '').toLowerCase();
    el.scrollIntoView({block:'center'});
    el.focus();
    if (tag === 'select') {
      el.value = value;
    } else {
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, value);
      else el.value = value;
    }
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
    el.blur();
    """, el, value)


def _select_or_type(driver, selectors: list[str], value: str, timeout: int = 3) -> bool:
    try:
        el = _find_any(driver, selectors, timeout=timeout)
    except Exception:
        return False
    try:
        tag = (el.tag_name or '').lower()
        if tag == 'select':
            if el.__class__.__name__ == 'CloakElement':
                driver.execute_script(r"""
                const el = arguments[0], value = String(arguments[1]);
                const n = parseInt(value, 10);
                const opts = [...el.options];
                const match = opts.find(o => o.value === value)
                  || opts.find(o => (o.textContent || '').trim() === value)
                  || opts[Math.max(0, n - 1)];
                if (match) el.value = match.value; else el.value = value;
                el.dispatchEvent(new Event('input', {bubbles:true}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
                """, el, str(value))
            else:
                from selenium.webdriver.support.ui import Select
                sel = Select(el)
                try:
                    sel.select_by_value(str(int(value)))
                except Exception:
                    try:
                        sel.select_by_visible_text(str(int(value)))
                    except Exception:
                        # The month select may be 0-based or 1-based; try value/text first, then index.
                        sel.select_by_index(max(0, int(value)-1))
                driver.execute_script("arguments[0].dispatchEvent(new Event('change', {bubbles:true}));", el)
        else:
            _human_type_text(driver, el, str(value), clear=True)
        return True
    except Exception as exc:
        logger.debug('%s Filling the field failed selectors=%s value=%s err=%s', _log_prefix(driver), selectors, value, exc)
        return False


def _fill_birthday_or_age(driver, birthday: str, age: int) -> str | None:
    """Fill in the age/birthday controls of about-you.

    Following FlowPilot: handle a direct age input first; otherwise be compatible with hidden birthday/date, native year/month/day
    select/input, React Aria hidden native select, role=spinbutton[data-type=year/month/day].
    Returns age / birthday / ymd / react_select / spinbutton / None.
    """
    y, m, d = birthday.split('-')
    result = driver.execute_script(r"""
    const birthday = String(arguments[0]);
    const year = String(arguments[1]);
    const month = String(Number(arguments[2]));
    const month2 = String(arguments[2]).padStart(2, '0');
    const day = String(Number(arguments[3]));
    const day2 = String(arguments[3]).padStart(2, '0');
    const age = String(arguments[4]);
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly;
    const setValue = (el, value) => {
      if (!el) return false;
      el.scrollIntoView?.({block:'center'});
      el.focus?.();
      const tag = (el.tagName || '').toLowerCase();
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype
        : tag === 'select' ? HTMLSelectElement.prototype
        : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, String(value)); else el.value = String(value);
      if (tag === 'select') {
        [...el.options].forEach(opt => { opt.selected = String(opt.value) === String(value); });
      }
      el.dispatchEvent(new Event('input', {bubbles:true}));
      el.dispatchEvent(new Event('change', {bubbles:true}));
      el.blur?.();
      return true;
    };
    const ageInput = [...document.querySelectorAll('input[name="age"], input#age, input[id$="-age"], input[type="number"]')]
      .find(visible);
    if (ageInput && setValue(ageInput, age)) return {ok:true, mode:'age'};

    const dateInput = [...document.querySelectorAll('input[name="birthdate"], input[type="date"], input[name="birthday"]')]
      .find(el => visible(el) || String(el.getAttribute('type') || '').toLowerCase() === 'date');
    if (dateInput && setValue(dateInput, birthday)) return {ok:true, mode:'birthday'};

    const setFirst = (selectors, values) => {
      for (const sel of selectors) {
        for (const el of [...document.querySelectorAll(sel)]) {
          if (!visible(el)) continue;
          for (const val of values) {
            if (el.tagName === 'SELECT') {
              const has = [...el.options].some(o => String(o.value) === String(val) || String(o.textContent || '').trim() === String(val));
              if (!has) continue;
            }
            if (setValue(el, val)) return true;
          }
        }
      }
      return false;
    };
    const yOk = setFirst(['select[name="year"]','input[name="year"]','select[id*="year"]','input[id*="year"]'], [year]);
    const mOk = setFirst(['select[name="month"]','input[name="month"]','select[id*="month"]','input[id*="month"]'], [month, month2]);
    const dOk = setFirst(['select[name="day"]','input[name="day"]','select[id*="day"]','input[id*="day"]'], [day, day2]);
    if (yOk && mOk && dOk) {
      const hidden = document.querySelector('input[name="birthday"]');
      if (hidden) setValue(hidden, birthday);
      return {ok:true, mode:'ymd'};
    }

    // React Aria Select Usually has a hidden native select; does not depend on label text, infers year/month/day from the option value range and DOM order.
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
    if (yearSelects.length && monthSelects.length && daySelects.length) {
      const ys = yearSelects[0];
      let ms = monthSelects[0];
      let ds = daySelects.find(x => x !== ms) || daySelects[0];
      setValue(ys, year);
      setValue(ms, hasOption(ms, month) ? month : month2);
      setValue(ds, hasOption(ds, day) ? day : day2);
      const hidden = document.querySelector('input[name="birthday"]');
      if (hidden) setValue(hidden, birthday);
      return {ok:true, mode:'react_select'};
    }

    const spinYear = document.querySelector('[role="spinbutton"][data-type="year"]');
    const spinMonth = document.querySelector('[role="spinbutton"][data-type="month"]');
    const spinDay = document.querySelector('[role="spinbutton"][data-type="day"]');
    if (spinYear && spinMonth && spinDay) return {ok:false, mode:'spinbutton_needed'};
    return {ok:false, mode:'missing'};
    """, birthday, y, m, d, str(age)) or {}
    if result.get('ok'):
        return str(result.get('mode') or 'birthday')
    if result.get('mode') != 'spinbutton_needed':
        return None

    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        mod = Keys.COMMAND
        try:
            import platform
            if platform.system().lower() != 'darwin':
                mod = Keys.CONTROL
        except Exception:
            pass
        for selector, value in [
            ('[role="spinbutton"][data-type="year"]', y),
            ('[role="spinbutton"][data-type="month"]', str(m).zfill(2)),
            ('[role="spinbutton"][data-type="day"]', str(d).zfill(2)),
        ]:
            el = driver.find_element(By.CSS_SELECTOR, selector)
            driver.execute_script("arguments[0].scrollIntoView({block:'center'}); arguments[0].focus();", el)
            time.sleep(0.1)
            el.send_keys(mod, 'a')
            time.sleep(0.05)
            el.send_keys(str(value))
            time.sleep(0.1)
            driver.execute_script("arguments[0].dispatchEvent(new Event('input', {bubbles:true})); arguments[0].dispatchEvent(new Event('change', {bubbles:true})); arguments[0].blur();", el)
        driver.execute_script(r"""
        const hidden = document.querySelector('input[name="birthday"]');
        if (hidden) {
          const value = arguments[0];
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (setter) setter.call(hidden, value); else hidden.value = value;
          hidden.dispatchEvent(new Event('input', {bubbles:true}));
          hidden.dispatchEvent(new Event('change', {bubbles:true}));
        }
        """, birthday)
        return 'spinbutton'
    except Exception as exc:
        logger.debug('%s spinbutton Filling the birthday failed:%s', _log_prefix(driver), exc)
        return None


def _generate_roxy_password() -> str:
    """Following the FlowPilot password policy: 8~64 characters, with upper and lower case, digits and symbols."""
    upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    lower = 'abcdefghjkmnpqrstuvwxyz'
    digits = '23456789'
    symbols = '!@#$%^&*?_-+=' 
    groups = [upper, lower, digits, symbols]
    all_chars = ''.join(groups)
    chars = [random.choice(g) for g in groups]
    while len(chars) < 14:
        chars.append(random.choice(all_chars))
    random.shuffle(chars)
    return ''.join(chars)


def _registration_password() -> str:
    try:
        from config import register as _register_cfg
        configured = str(getattr(_register_cfg, 'REGISTER_PASSWORD', '') or '').strip()
        if configured:
            return configured
    except Exception:
        pass
    return _generate_roxy_password()


def _password_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const inputs = [...document.querySelectorAll('input')].map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', visible: visible(el), value: el.type === 'password' ? '<password>' : (el.value || '')
        })).slice(0, 30);
        const forms = [...document.querySelectorAll('form')].map(f => ({action: f.getAttribute('action') || ''}));
        const buttons = [...document.querySelectorAll('button,input[type="submit"]')].map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          disabled: !!el.disabled, visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).slice(0, 30);
        const errors = [...document.querySelectorAll('[role="alert"],[aria-live="assertive"],[aria-live="polite"],.react-aria-FieldError,[slot="errorMessage"],[class*="error"]')]
          .filter(el => visible(el)).map(el => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean).slice(0, 10);
        return {url: location.href, inputs, forms, buttons, errors};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _is_signup_password_page(driver) -> bool:
    state = _password_page_state(driver)
    # execute_script may fail briefly right after the page finished navigating; the URL is still enough to confirm this is the registration password page,
    # so it must not return None early, which would wrongly enter the OTP input stage afterwards.
    url = str(state.get('url') or getattr(driver, 'current_url', '') or '').lower()
    if any(x in url for x in ('/create-account/password', '/u/signup/password', '/signup/password')):
        return True
    if '/log-in/password' in url:
        return False
    inputs = state.get('inputs') or []
    return any(
        i.get('visible') and (
            str(i.get('type') or '').lower() == 'password'
            or 'password' in str(i.get('name') or '').lower()
            or str(i.get('autocomplete') or '').lower() == 'new-password'
        )
        for i in inputs
    )


def _is_login_password_page(driver) -> bool:
    try:
        url = str(driver.current_url or '').lower()
    except Exception:
        url = ''
    if '/log-in/password' in url:
        return True
    state = _password_page_state(driver)
    url = str(state.get('url') or '').lower()
    return '/log-in/password' in url


def _resubmit_signup_password_form(driver) -> dict:
    """When clicking on the password page does not navigate, run a native requestSubmit on the current password form once."""
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
          .find(visible);
        const form = input?.closest('form');
        const button = form ? [...form.querySelectorAll('button[type="submit"],input[type="submit"],button')]
          .find(el => visible(el) && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true') : null;
        const errors = [...document.querySelectorAll('[role="alert"],[aria-live="assertive"],[aria-live="polite"],.react-aria-FieldError,[slot="errorMessage"],[class*="error"]')]
          .filter(visible).map(el => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean).slice(0, 10);
        if (!input || !form) return {ok:false, reason:'missing_password_form', url:location.href, errors};
        if (!String(input.value || '')) return {ok:false, reason:'empty_password', url:location.href, errors};
        if (errors.length) return {ok:false, reason:'page_errors', url:location.href, errors};
        if (typeof form.requestSubmit === 'function') form.requestSubmit(button || undefined);
        else if (button) button.click();
        else form.submit();
        return {ok:true, reason:'form_requestSubmit', url:location.href, valueLength:String(input.value || '').length};
        """) or {"ok": False, "reason": "empty_result"}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _click_passwordless_signup_if_present(driver) -> dict:
    """
    The new registration/login flow may require a password by default on the password page.
    If the page offers a "use a one-time code" button, prefer clicking it to enter the email OTP page.
    """
    try:
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const candidates = [...document.querySelectorAll('button,a,input[type="submit"],[role="button"],[role="link"]')].filter(el => visible(el) && enabled(el));
        const isPasswordlessOtp = el => {
          const name = String(el.getAttribute('name') || '').toLowerCase();
          const value = String(el.getAttribute('value') || '').toLowerCase();
          const attrs = [
            el.id, name, value, el.getAttribute('aria-label'), el.getAttribute('title'),
            el.getAttribute('data-testid'), el.getAttribute('data-dd-action-name'), el.className, el.textContent
          ].join(' ').toLowerCase();
          const text = norm(el.textContent || el.getAttribute('value') || '');
          return (
            (name === 'intent' && value.includes('passwordless') && value.includes('send_otp')) ||
            (name === 'intent' && value.includes('passwordless') && value.includes('otp')) ||
            (name === 'intent' && value === 'passwordless_signup_send_otp') ||
            (name === 'intent' && value === 'passwordless_login_send_otp') ||
            attrs.includes('passwordless_signup_send_otp') ||
            attrs.includes('passwordless_login_send_otp') ||
            /passwordless.*otp|otp.*passwordless|one[-_\s]?time.*code|code.*one[-_\s]?time/.test(attrs) ||
            text.includes('使用一次性验证码注册') ||
            text.includes('使用一次性验证码登录') ||
            text.includes('使用一次性验证码') ||
            text.includes('使用一次性驗證碼註冊') ||
            text.includes('使用一次性驗證碼登入') ||
            text.includes('一次性验证码') ||
            text.includes('一次性驗證碼') ||
            text.includes('メールでコード') ||
            text.includes('ワンタイムコード') ||
            text.includes('認証コード') ||
            text.includes('useonetimeregistrationcode') ||
            text.includes('useaone-timecodetosignup') ||
            text.includes('useaone-timecodetoregister') ||
            text.includes('useaone-timecodetologin') ||
            text.includes('continuewithaone-timecode') ||
            text.includes('loginwithaone-timecode') ||
            text.includes('signupwithaone-timecode') ||
            text.includes('one-timecode')
          );
        };
        const btn = candidates.find(isPasswordlessOtp);
        if (!btn) return {ok:false, reason:'missing_passwordless_button'};
        btn.scrollIntoView({block:'center'});
        return {
          ok:true,
          reason:'passwordless_send_otp_target',
          button: btn,
          name: btn.getAttribute('name') || '',
          value: btn.getAttribute('value') || '',
          text: (btn.textContent || '').trim().slice(0, 80)
        };
        """) or {"ok": False, "reason": "empty_result"}
        if result.get("ok") and result.get("button"):
            _human_click(driver, result.get("button"), label="passwordless_otp")
            result["reason"] = "clicked_passwordless_send_otp"
            result.pop("button", None)
        return result
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _click_continue_with_password_if_present(driver) -> dict:
    """On the email verification code page click 'continue with password' to enter /create-account/password."""
    try:
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const candidates = [...document.querySelectorAll('a,button,input[type="button"],input[type="submit"],[role="link"],[role="button"],[data-login-web-auth-control],[data-dd-action-name]')]
          .filter(el => visible(el) && enabled(el));
        const isPasswordCreate = el => {
          const href = String(el.getAttribute('href') || '').toLowerCase();
          const attrs = [
            href, el.id, el.getAttribute('aria-label'), el.getAttribute('title'),
            el.getAttribute('data-testid'), el.getAttribute('data-login-web-auth-control'),
            el.getAttribute('data-dd-action-name'), el.className, el.textContent
          ].join(' ').toLowerCase();
          const text = norm(el.innerText || el.textContent || '');
          const passwordContinue = /continuewithpassword|continuewithapassword|usepasswordtocontinue|continueusingpassword/.test(text)
            || /密码.*继续|密碼.*繼續|비밀번호.*계속|パスワード.*続行|パスワード.*つづける/.test(text);
          return (
            href.includes('/create-account/password') ||
            attrs.includes('/create-account/password') ||
            passwordContinue
          );
        };
        const btn = candidates.find(isPasswordCreate);
        if (!btn) return {ok:false, reason:'missing_continue_with_password'};
        btn.scrollIntoView({block:'center'});
        return {
          ok:true,
          reason:'continue_with_password_target',
          button: btn,
          href: btn.getAttribute('href') || '',
          text: (btn.textContent || '').trim().slice(0, 80)
        };
        """) or {"ok": False, "reason": "empty_result"}
        if result.get("ok") and result.get("button"):
            _human_click(driver, result.get("button"), label="continue_with_password")
            result["reason"] = "clicked_continue_with_password"
            result.pop("button", None)
        return result
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _fill_password_page_if_present(driver, email: str, timeout: int = 25) -> str | None:
    """After the email submit also compatible with create-account/password. Returns the OpenAI account password set this time; returns None if no password page was met."""
    end = time.time() + timeout
    verification_wait_end = min(end, time.time() + 10)
    last = {}
    missing_element_refreshes = 0
    password_route_requested = False
    while time.time() < end:
        if _is_email_verification_page(driver):
            result = {}
            for _ in range(8):
                result = _click_continue_with_password_if_present(driver)
                if result.get("ok"):
                    logger.info("%s Clicked 'continue with password' on the email verification code page:email=%s detail=%s", _log_prefix(driver), email, result)
                    # After the click the navigation may take more than ten seconds under a high-latency proxy. The old logic only waited 0.8 seconds before clicking again,
                    # keeping the original 25-second total deadline, so in the end it could return None exactly when the password page had just appeared
                    # . After the first click, navigation/render time is reserved separately and we wait for the state to really change.
                    if not password_route_requested:
                        password_route_requested = True
                        end = max(end, time.time() + 40)
                    navigation_end = min(end, time.time() + 12)
                    while time.time() < navigation_end:
                        if _is_signup_password_page(driver) or _has_access_token(driver):
                            break
                        if not _is_email_verification_page(driver):
                            break
                        time.sleep(0.5)
                    break
                time.sleep(0.5)
            else:
                if time.time() < verification_wait_end:
                    logger.info("%s 'Continue with password' not found yet on the email verification code page, continuing to wait for the page to render:detail=%s", _log_prefix(driver), result)
                    time.sleep(0.5)
                    continue
                if _refresh_after_missing_page_element(driver, "continue-with-password button", missing_element_refreshes):
                    missing_element_refreshes += 1
                    end = time.time() + timeout
                    verification_wait_end = min(end, time.time() + 10)
                    continue
                logger.info("%s Already on the email verification code page, but the 'continue with password' button was not found:detail=%s", _log_prefix(driver), result)
                return None
            continue
        if _has_access_token(driver):
            return None
        last = _password_page_state(driver)
        is_signup_password = _is_signup_password_page(driver)
        is_login_password = _is_login_password_page(driver)
        if not (is_signup_password or is_login_password):
            time.sleep(0.5)
            continue
        passwordless = _click_passwordless_signup_if_present(driver) if is_login_password else {"ok": False, "reason": "signup_password_prefers_password"}
        if passwordless.get('ok'):
            logger.info("%s Password page detected, clicked the one-time code entry:email=%s detail=%s", _log_prefix(driver), email, passwordless)
            wait_end = time.time() + 20
            while time.time() < wait_end:
                if _is_email_verification_page(driver):
                    logger.info("%s Entered the email verification code page through the one-time code entry", _log_prefix(driver))
                    return None
                if _has_access_token(driver):
                    logger.info("%s Login state detected after the one-time code entry", _log_prefix(driver))
                    return None
                time.sleep(0.5)
            logger.info("%s Clicked the one-time code entry, the OTP page was not detected immediately, leaving it to the following OTP stage", _log_prefix(driver))
            return None
        if is_login_password:
            logger.info("%s This is the login password page but no one-time code entry was found, skipping the password fill and leaving it to the OTP stage:state=%s", _log_prefix(driver), last)
            return None
        password = _registration_password()
        logger.info("%s create-account/password detected, preparing to set the password (%s characters):email=%s", _log_prefix(driver), len(password), email)
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_password_input'};
        const form = input.closest('form');
        const scope = form || document;
        const buttons = [...scope.querySelectorAll('button,input[type="submit"]')]
          .filter(el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled && el.getAttribute('aria-disabled') !== 'true')
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
        if not result.get('ok'):
            reason = str(result.get('reason') or '')
            if reason in {'missing_password_input', 'missing_submit'} and _refresh_after_missing_page_element(
                driver, "password input box / submit button", missing_element_refreshes
            ):
                missing_element_refreshes += 1
                end = time.time() + timeout
                continue
            raise RuntimeError(f"Password page handling failed:{result} state={last}")
        _human_type_text(driver, result.get("input"), password, clear=True)
        # React/Auth0 will asynchronously validate the password strength after input/change and enable Continue.
        # It used to click 0.4~1.4s after typing, occasionally clicking before the button was really submittable / events were bound, and the page did not react.
        human_delay("form", minimum=2.0, maximum=3.6)
        submit_result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => !!el && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const pass = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
          .find(el => visible(el) && !el.disabled && !el.readOnly);
        const form = pass ? pass.closest('form') : document.querySelector('form');
        const scope = form || document;
        const candidates = [...scope.querySelectorAll('button,input[type="submit"],[role="button"]')]
          .filter(el => visible(el) && enabled(el));
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const scored = candidates.map((el, idx) => {
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
          return {el, idx, score};
        }).sort((a,b) => b.score - a.score || a.idx - b.idx);
        const target = scored[0]?.el;
        if (!target) return {ok:false, reason:'missing_enabled_submit'};
        target.scrollIntoView({block:'center'});
        return {
          ok:true,
          reason:'enabled_submit_target',
          button: target,
          text: (target.textContent || target.getAttribute('value') || '').trim().slice(0, 80),
          type: target.getAttribute('type') || '',
          dd: target.getAttribute('data-dd-action-name') || '',
          ariaDisabled: target.getAttribute('aria-disabled') || ''
        };
        """) or {}
        if not submit_result.get("ok") or not submit_result.get("button"):
            reason = str(submit_result.get('reason') or '')
            if reason == 'missing_enabled_submit' and _refresh_after_missing_page_element(
                driver, "password page Continue button", missing_element_refreshes
            ):
                missing_element_refreshes += 1
                end = time.time() + timeout
                continue
            raise RuntimeError(f"Cannot find a clickable Continue button on the password page:{submit_result} state={_password_page_state(driver)}")
        _human_click(driver, submit_result.get("button"), label="password_submit")
        logger.info("%s Filled in and clicked Continue on the password page:detail=%s", _log_prefix(driver), {k: v for k, v in submit_result.items() if k != "button"})
        # Under a high-latency proxy the Auth0 submit and navigation may clearly exceed 20 seconds; entering the OTP stage too early
        # would look for the verification code box on /create-account/password. Enough submit/navigation time is given here.
        wait_end = time.time() + 60
        retried_submit = False
        while time.time() < wait_end:
            if _is_email_verification_page(driver):
                logger.info("%s Entered the email verification code page after the password submit", _log_prefix(driver))
                return password
            if _has_access_token(driver):
                logger.info("%s Login state detected after the password submit", _log_prefix(driver))
                return password
            if _is_signup_password_page(driver):
                error_state = _password_page_state(driver)
                errors = error_state.get("errors") or []
                if errors:
                    error_text = ";".join(str(item) for item in errors[:3])
                    raise RuntimeError(
                        f"Password page submit rejected: {error_text} "
                        f"url={error_state.get('url') or getattr(driver, 'current_url', '')}"
                    )
            if not retried_submit and time.time() > wait_end - 42 and _is_signup_password_page(driver):
                retried_submit = True
                retry_result = _resubmit_signup_password_form(driver)
                logger.info("%s The password page did not navigate after the click, doing one native form resubmit:%s", _log_prefix(driver), retry_result)
                if retry_result.get("reason") == "page_errors":
                    raise RuntimeError(f"Password page submit was rejected by the page: {retry_result}")
            if not _is_signup_password_page(driver):
                return password
            time.sleep(0.5)
        # When the password submit times out while still on the registration password page, "password already set" must not be treated as success and
        # handed directly to the following OTP stage; the OTP input box certainly does not exist then. Fail explicitly and keep
        # the current URL/DOM diagnostics, to avoid pointlessly refreshing the password page three times.
        if _is_signup_password_page(driver):
            current_url = str(getattr(driver, "current_url", "") or "")
            raise RuntimeError(f"Still on the registration password page after the password submit: url={current_url} state={_password_page_state(driver)}")
        return password
    # If switching to the password method has already been requested, silently entering the OTP stage during a navigation race is not allowed.
    # Read the browser URL one last time; when the password route has been reached but the DOM is not ready, report an error explicitly,
    # to avoid refreshing the password page repeatedly afterwards while looking for the OTP input box.
    current_url = str(getattr(driver, "current_url", "") or "")
    if password_route_requested and any(x in current_url.lower() for x in (
        "/create-account/password", "/u/signup/password", "/signup/password",
    )):
        raise RuntimeError(f"Entered the registration password page but the password form was not ready within the wait deadline: url={current_url} state={last}")
    logger.info("%s Password page not detected, continuing with the following flow last=%s", _log_prefix(driver), last)
    return None


def _accept_profile_consents(driver) -> int:
    """about-you/profile When a Korea/Japan personal-information consent agreement appears, tick all by default.

    Does not depend on visible text; handle allCheckboxes first, then all required consent checkboxes.
    """
    try:
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled;
        const isChecked = el => el.checked === true || String(el.getAttribute('aria-checked') || el.closest('[role="checkbox"]')?.getAttribute('aria-checked') || '').toLowerCase() === 'true';
        const mark = el => {
          if (!el || isChecked(el)) return false;
          const label = el.closest('label');
          try {
            (label && visible(label) ? label : el).scrollIntoView({block:'center'});
            (label && visible(label) ? label : el).click();
          } catch (_) {}
          if (!isChecked(el)) {
            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set;
            if (setter) setter.call(el, true); else el.checked = true;
            el.dispatchEvent(new MouseEvent('click', {bubbles:true}));
            el.dispatchEvent(new Event('input', {bubbles:true}));
            el.dispatchEvent(new Event('change', {bubbles:true}));
          }
          return isChecked(el);
        };
        const all = [...document.querySelectorAll('input[type="checkbox"]')]
          .filter(el => visible(el) || visible(el.closest('label')));
        if (!all.length) return {count:0, names:[]};
        const byName = name => all.find(el => String(el.name || '').toLowerCase() === name.toLowerCase());
        const ordered = [];
        const add = el => { if (el && !ordered.includes(el)) ordered.push(el); };
        add(byName('allCheckboxes'));
        for (const name of ['personalInfoConsent', 'thirdPartyConsent', 'overseasTransferConsent']) add(byName(name));
        for (const el of all) {
          const n = String(el.name || '').toLowerCase();
          const id = String(el.id || '').toLowerCase();
          if (/consent|checkbox|agree|required|personal|third|overseas/.test(`${n} ${id}`)) add(el);
        }
        // about-you/profile The checkboxes in the page are basically all required consents; the remaining visible checkboxes are all ticked too.
        for (const el of all) add(el);
        const clicked = [];
        for (const el of ordered) {
          if (mark(el)) clicked.push(el.name || el.id || 'checkbox');
        }
        return {count: clicked.length, names: clicked};
        """) or {}
        count = int(result.get('count') or 0)
        if count:
            logger.info("%s Ticked the about-you/profile consent checkboxes:%s", _log_prefix(driver), result.get('names'))
        return count
    except Exception as exc:
        logger.debug('%s Ticking the profile consent failed%s', _log_prefix(driver), exc)
        return 0


def _complete_profile_page(driver, name: str, birthday: str, timeout: int = 45) -> bool:
    """Wait for and complete the name/birthday page; if already logged in successfully return False, and do not treat it as a failure."""
    end = time.time() + timeout
    y, m, d = birthday.split('-')
    from datetime import date
    today = date.today()
    age = today.year - int(y) - ((today.month, today.day) < (int(m), int(d)))
    last_snapshot = {}
    while time.time() < end:
        time.sleep(1)
        if _has_access_token(driver):
            logger.info('%s Login state detected, the profile page may have been skipped', _log_prefix(driver))
            return False
        snap = _page_snapshot(driver)
        last_snapshot = snap
        if not _is_profile_like(snap):
            logger.info('%s Waiting for the profile page:url=%s', _log_prefix(driver), snap.get('url'))
            continue

        logger.info('%s Profile page detected, starting to fill in the name and birthday:url=%s inputs=%s', _log_prefix(driver), snap.get('url'), snap.get('inputs'))
        name_ok = False
        # Common single name field
        for selectors in [
            ["input[name='name']", "input[name='fullName']", "input[name='full_name']", "input[autocomplete='name']"],
            ["input[placeholder*='Name']", "input[placeholder*='name']", "input[aria-label*='Name']", "input[aria-label*='name']"],
        ]:
            if _select_or_type(driver, selectors, name, timeout=3):
                logger.info("%s Filled in the name field:%s", _log_prefix(driver), name)
                name_ok = True
                break
        # Compatible with separate first/last
        if not name_ok:
            parts = name.split(' ', 1)
            first = parts[0]
            last = parts[1] if len(parts) > 1 else 'User'
            first_ok = _select_or_type(driver, ["input[name='firstName']", "input[name='first_name']", "input[placeholder*='First']", "input[aria-label*='First']"], first, timeout=2)
            last_ok = _select_or_type(driver, ["input[name='lastName']", "input[name='last_name']", "input[placeholder*='Last']", "input[aria-label*='Last']"], last, timeout=2)
            name_ok = first_ok or last_ok

        birth_mode = _fill_birthday_or_age(driver, birthday, age)
        birth_ok = bool(birth_mode)
        if birth_ok:
            if birth_mode == 'age':
                logger.info("%s Filled in the age field:%s", _log_prefix(driver), age)
            else:
                logger.info("%s Filled in the birthday field mode=%s value=%s", _log_prefix(driver), birth_mode, birthday)

        if not name_ok or not birth_ok:
            logger.warning('%s Profile page fields not completely filled name_ok=%s birth_ok=%s snapshot=%s', _log_prefix(driver), name_ok, birth_ok, snap)
            continue

        _accept_profile_consents(driver)
        human_delay('form')
        for _ in range(3):
            if _click_if_enabled_submit(driver):
                logger.info('%s Clicked the profile page submit button, waiting for the OAuth redirect', _log_prefix(driver))
                return True
            time.sleep(1)
        logger.warning('%s No clickable profile page submit button found snapshot=%s', _log_prefix(driver), _page_snapshot(driver))
    raise RuntimeError(f'Timed out waiting for / filling in the profile page, last page:{last_snapshot}')


def _click_if_enabled_submit(driver) -> bool:
    """Submit the profile page: prefer form.requestSubmit/button[type=submit], not depending on button text."""
    try:
        target = driver.execute_script(r"""
        const visible = (el) => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const forms = [...document.querySelectorAll('form')].filter(visible);
        for (const form of forms) {
          const submit = form.querySelector('button[type="submit"], input[type="submit"]');
          if (submit && visible(submit) && !submit.disabled) {
            submit.scrollIntoView({block:'center'});
            return submit;
          }
          if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
            return 'submitted_by_requestSubmit';
          }
        }
        const submitters = [...document.querySelectorAll('button[type="submit"], input[type="submit"]')]
          .filter(el => visible(el) && !el.disabled);
        if (submitters.length) {
          submitters[0].scrollIntoView({block:'center'});
          return submitters[0];
        }
        // Fallback: when the page has only one clickable button, click it, still without reading text.
        const buttons = [...document.querySelectorAll('button:not([disabled])')].filter(visible);
        if (buttons.length === 1) {
          buttons[0].scrollIntoView({block:'center'});
          return buttons[0];
        }
        return null;
        """)
        if not target:
            return False
        if isinstance(target, str):
            return True
        _human_click(driver, target, label="profile_submit")
        return True
    except Exception:
        return False


def _read_chatgpt_session_once(driver) -> dict | None:
    """The current page must be on chatgpt.com; read /api/auth/session, return None if no token is obtained."""
    script = r"""
    const done = arguments[0];
    fetch('/api/auth/session', {credentials: 'include'})
      .then(r => r.json())
      .then(j => done({ok: true, data: j}))
      .catch(e => done({ok: false, error: String(e)}));
    """
    result = driver.execute_async_script(script)
    if result and result.get("ok"):
        data = result.get("data") or {}
        if data.get("accessToken"):
            logger.info("%s /api/auth/session returned accessToken", _log_prefix(driver))
            return data
        logger.info("%s Waiting for the ChatGPT session to write the accessToken, current response keys=%s", _log_prefix(driver), list(data.keys()))
    return None


def _switch_to_chatgpt_window_if_any(driver) -> bool:
    """Some browsers/adapter layers finish the callback in a new window; try switching to an existing chatgpt.com handle."""
    try:
        handles = list(getattr(driver, "window_handles", []) or [])
        current_handle = None
        try:
            current_handle = getattr(driver, "current_window_handle", None)
        except Exception:
            current_handle = None
        for handle in handles:
            try:
                driver.switch_to.window(handle)
                if "chatgpt.com" in str(getattr(driver, "current_url", "") or ""):
                    return True
            except Exception:
                continue
        if current_handle is not None:
            try:
                driver.switch_to.window(current_handle)
            except Exception:
                pass
    except Exception:
        pass
    return False


def _fetch_chatgpt_session(driver, timeout: int = 90, auto_jump_wait: int = 15) -> dict:
    """Wait for the page to finish navigating and read the login session/accessToken from inside the ChatGPT page.

    The old logic would wait on auth.openai.com until the total timeout; in Cloak / some Chromium scenarios
    the account was actually created successfully but the URL of the current handle was not updated in time, wasting 120 seconds. Now only
    `auto_jump_wait` seconds are given for the automatic redirect; after that chatgpt.com is opened actively to read the session.
    """
    end = time.time() + timeout
    auto_jump_end = time.time() + max(3, int(auto_jump_wait or 15))
    last_data = None
    forced_chatgpt_open = False

    while time.time() < end:
        try:
            current = str(driver.current_url or '')
        except Exception:
            current = ''

        if 'chatgpt.com' not in current:
            if _switch_to_chatgpt_window_if_any(driver):
                current = str(getattr(driver, "current_url", "") or "")
            elif time.time() >= auto_jump_end and not forced_chatgpt_open:
                try:
                    logger.info("%s The current window was not seen jumping to chatgpt.com within %ss, actively opening ChatGPT to read session", _log_prefix(driver), int(auto_jump_wait or 15))
                    _safe_get(driver, "https://chatgpt.com/", timeout=35, attempts=2, accept_hosts=("chatgpt.com",))
                    forced_chatgpt_open = True
                    time.sleep(3)
                    current = str(getattr(driver, "current_url", "") or "")
                except Exception as exc:
                    last_data = f"{type(exc).__name__}: {exc}"
            else:
                time.sleep(1)
                continue

        if 'chatgpt.com' in current:
            try:
                data = _read_chatgpt_session_once(driver)
                if data:
                    return data
                last_data = "session none yet accessToken"
            except Exception as exc:
                last_data = f"{type(exc).__name__}: {exc}"
        time.sleep(2)

    raise RuntimeError(f"Timed out waiting for the /api/auth/session accessToken, last response: {str(last_data)[:800]}")


def _check_manual_stop() -> None:
    try:
        from core.registration_service import check_stop_requested
        check_stop_requested()
    except ImportError:
        return


def run_roxy_registration(
    email: str | None,
    name: str,
    birthday: str,
    proxy: str = None,
    otp_code: str = None,
    batch_dir: Path | None = None,
    on_email_acquired: Callable[[str], None] | None = None,
) -> dict:
    """Roxy fingerprint browser automated registration entry point."""
    client = RoxyBrowserClient()
    opened = client.open_profile()
    driver = None
    create_acknowledged = False
    openai_password: str | None = None
    traffic_tracker: SeleniumTrafficTracker | None = None
    data_saver: BrowserDataSaver | None = None
    asset_cache: RoxyLocalAssetCache | None = None
    asset_cache_snapshot: dict | None = None
    network_traffic: dict | None = None

    def _merge_proxy_transport_traffic() -> None:
        """Correct the CDP statistics, which only cover the current page target, with the full count of the proxy chain."""
        nonlocal network_traffic
        network_traffic = merge_proxy_transport_traffic(
            network_traffic, client.proxy_transport_snapshot(), label="Roxy",
        )

    def _traffic_checkpoint() -> None:
        if traffic_tracker is not None:
            try:
                traffic_tracker.checkpoint()
            except Exception as exc:
                logger.debug("[Roxy registration] Failed to refresh the browser traffic statistics:%s", exc)

    try:
        driver = _build_driver(opened)
        try:
            asset_cache = RoxyLocalAssetCache(opened.debugger_address, label="Roxy").start()
        except Exception as exc:
            logger.warning("[Roxy registration] Failed to initialize the local static resource cache, continuing to load online:%s: %s", type(exc).__name__, str(exc)[:180])
        try:
            traffic_tracker = SeleniumTrafficTracker(driver, label="Roxy")
        except Exception as exc:
            # A statistics failure must not affect the registration main flow.
            logger.warning("[Roxy registration] Failed to initialize the browser traffic statistics, continuing the registration:%s: %s", type(exc).__name__, str(exc)[:180])
        data_saver = BrowserDataSaver(label="Roxy")
        if traffic_tracker is not None:
            traffic_tracker.attach_data_saver(data_saver)
            traffic_tracker.attach_local_asset_cache(asset_cache)
        data_saver.install_selenium(driver)
        _center_browser_window(driver)
        driver.set_page_load_timeout(int(_cfg.ROXY_SELENIUM_TIMEOUT))
        try:
            driver.set_script_timeout(12)
        except Exception:
            pass
        logger.info("[Roxy registration] Start: %s,profile=%s", email, opened.profile_id)

        otp_after_ts = time.time()
        logger.info("[Roxy registration] Opening the login page:https://chatgpt.com/auth/login")
        _safe_get(
            driver,
            "https://chatgpt.com/auth/login",
            timeout=min(45, int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)),
            attempts=2,
            accept_hosts=("chatgpt.com", "auth.openai.com"),
        )
        _traffic_checkpoint()
        human_delay("navigate")
        _page_warmup(driver, reason="login_page")
        logger.info("[Roxy registration] Login page loaded, preparing to fill in the email")
        _maybe_accept(driver)
        _check_manual_stop()

        # Fill in the email. The OpenAI UI changes with the exit IP / language; here the email entry is found only by DOM technical attributes,
        # and third-party entries such as Google/Apple/Microsoft are excluded, not depending on visible button text.
        def _email_supplier_after_input() -> str:
            nonlocal email
            _check_manual_stop()
            email = acquire_email_after_input(email)
            if on_email_acquired:
                on_email_acquired(email)
            return email

        next_state = _submit_email_and_wait_next(
            driver,
            email,
            attempts=3,
            email_supplier=_email_supplier_after_input,
        )
        _traffic_checkpoint()
        _check_manual_stop()

        # If the new registration flow goes straight to the verification code page after the email, also prefer clicking "continue with password" to enter
        # /create-account/password, set a password and write it into account extra.registration_password.
        openai_password = _fill_password_page_if_present(driver, email, timeout=25)
        _traffic_checkpoint()
        _check_manual_stop()

        # Defensive check: no password page handling branch may hand a page still on the password route to the
        # OTP input logic, otherwise it would only refresh the password page and report "OTP input box not found".
        if _is_signup_password_page(driver):
            raise RuntimeError(
                f"Still on the registration password page after the password page handling ended: "
                f"url={getattr(driver, 'current_url', '')} state={_password_page_state(driver)}"
            )

        current_otp = otp_code
        max_otp_attempts = 3
        for otp_attempt in range(1, max_otp_attempts + 1):
            if current_otp is None:
                logger.info("[Roxy registration][OTP] Waiting for the verification code: %s (attempt %s/%s)", email, otp_attempt, max_otp_attempts)
                try:
                    current_otp = wait_for_otp(email, after_ts=otp_after_ts)
                except Exception as exc:
                    if otp_attempt >= max_otp_attempts:
                        raise
                    # Fallback: when OpenAI resends a verification code it is often the same email (timestamp unchanged),
                    # after_ts and the filter would ignore it as an old email. First fetch the latest verification code leniently,
                    # and if obtained retry the submit with it directly, to avoid a dead wait after wrongly clicking "resend".
                    fallback_otp = None
                    try:
                        fallback_otp = wait_for_otp(email, after_ts=0.0, max_wait=15, poll_interval=3)
                    except Exception:
                        fallback_otp = None
                    if fallback_otp:
                        logger.info(
                            "[Roxy registration][OTP] The code retrieval API timed out but the latest verification code was obtained leniently, retrying the submit directly:%s (fallback)",
                            fallback_otp,
                        )
                        current_otp = fallback_otp
                        continue
                    logger.warning(
                        "[Roxy registration][OTP] No verification code received for a long time, clicking 'resend email' and continuing to wait (next round %s/%s):%s: %s",
                        otp_attempt + 1,
                        max_otp_attempts,
                        type(exc).__name__,
                        str(exc)[:180],
                    )
                    otp_after_ts = time.time()
                    _click_resend_email_otp(driver, timeout=25)
                    human_delay("api")
                    current_otp = None
                    continue
            logger.info("[Roxy registration][OTP] Verification code received:%s", current_otp)
            _clear_otp_inputs(driver)
            _type_otp(driver, current_otp)
            logger.info("[Roxy registration][OTP] Filled in the email verification code")
            _check_manual_stop()
            human_delay("otp_input")
            try:
                _click_continue(driver)
                logger.info("[Roxy registration][OTP] Submitted the email verification code, waiting for the profile page or the login state")
            except Exception as exc:
                logger.info("[Roxy registration][OTP] No explicit submit button found, continuing to wait for the page state:%s", str(exc)[:120])

            outcome = _wait_after_email_otp_submit(driver, timeout=30)
            _traffic_checkpoint()
            if outcome == 'accepted':
                break
            if otp_attempt >= max_otp_attempts:
                raise RuntimeError("Email verification code wrong/expired repeatedly, the maximum number of retries has been reached")
            logger.warning("[Roxy registration][OTP] Verification code wrong/expired, preparing to resend and fetch a new verification code (%s/%s)", otp_attempt + 1, max_otp_attempts)
            otp_after_ts = time.time()
            _click_resend_email_otp(driver, timeout=25)
            _traffic_checkpoint()
            human_delay("api")
            current_otp = None

        # about-you / profile information page: must be completed or an existing login state confirmed, it must not be skipped silently.
        logger.info("[Roxy registration] Starting to wait for the profile page / login state")
        _check_manual_stop()
        profile_submitted = _complete_profile_page(driver, name, birthday, timeout=60)
        _traffic_checkpoint()
        if profile_submitted:
            create_acknowledged = True
            # Give the OAuth callback / session cookie write a little time.
            human_delay("post_auth")

        logger.info("[Roxy registration] Waiting for ChatGPT to redirect and write session/accessToken")
        _check_manual_stop()
        session_info = _fetch_chatgpt_session(driver, timeout=120)
        _traffic_checkpoint()
        access_token = session_info["accessToken"]
        logger.info("[Roxy registration] Got the accessToken:%s", email)
        _check_manual_stop()
        # After the accessToken is obtained the ChatGPT app shell is no longer needed; when Codex reuses the current window the complete page is kept.
        try:
            from config import codex as _codex_deep_cfg
            if not bool(getattr(_codex_deep_cfg, "ENABLE_CODEX_AUTO", False)) and data_saver is not None:
                data_saver.enable_post_auth_deep_mode(driver)
                # When Codex is not needed, switch to a local blank page and stop the polling and telemetry of the ChatGPT SPA
                # and lazy-loaded resources; the accessToken has already been taken from the data needed for persistence in the previous step.
                try:
                    driver.get("about:blank")
                    logger.info("[Roxy registration] Switched to about:blank, stopping the background page traffic after registration")
                except Exception as blank_exc:
                    logger.debug("[Roxy registration] Switching to the blank page failed, keeping the deep blocking:%s", blank_exc)
        except Exception as exc:
            logger.debug("[Roxy registration] Deep traffic-saving stage skipped:%s", exc)

        if _twofa_cfg.ENABLE_2FA:
            logger.warning("[Roxy registration] The current Roxy automation path does not run the 2FA setup for now, skipped")
        totp_secret = None

        codex_result = {
            "status": "skipped",
            "ok": True,
            "message": "ENABLE_CODEX_AUTO=False, skipping Codex",
        }
        try:
            from config import codex as _codex_cfg
            if bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False)):
                # The registration flow itself has already created one Roxy environment per account. A second Roxy environment must not be created here;
                # reuse the current registration window, first clean the Cookie/session/localStorage/cache, then start the Codex authorization.
                from core.roxy_codex_oauth import run_roxy_codex_oauth
                logger.info("[Roxy registration][Codex] ENABLE_CODEX_AUTO=True, reusing the current registration Roxy window to run the Codex authorization, no new environment is created")
                _check_manual_stop()
                codex_result = run_roxy_codex_oauth(
                    email,
                    reuse_existing_profile=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    force=True,
                    clear_existing_state=True,
                )
                _traffic_checkpoint()
            else:
                logger.info("[Roxy registration][Codex] ENABLE_CODEX_AUTO=False, skipped after registration Codex OAuth")
        except Exception as exc:
            codex_result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {str(exc)[:180]}"}

        # Count the complete session before the registration browser closes; network requests during the post-registration dwell are counted too.
        post_register_dwell(email, label="Roxy registration")
        _traffic_checkpoint()
        if asset_cache is not None:
            asset_cache_snapshot = asset_cache.stop()
        if traffic_tracker is not None:
            network_traffic = traffic_tracker.stop()
        if asset_cache_snapshot is not None:
            if not isinstance(network_traffic, dict):
                network_traffic = {}
            network_traffic["local_asset_cache"] = asset_cache_snapshot
        _merge_proxy_transport_traffic()
        if data_saver is not None:
            data_saver.stop()
        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(email),
            proxy_used=((opened.raw or {}).get("proxy_pool_target") if opened else None) or proxy or None,
            batch_dir=batch_dir,
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "roxybrowser": {"profile_id": opened.profile_id, "open_result": opened.raw},
                "registration_password": openai_password,
                "codex": codex_result,
                "network_traffic": network_traffic,
            },
        )
        codex_ok = codex_result.get("ok") or codex_result.get("status") == "skipped"
        return {
            "success": bool(codex_ok),
            "email": email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": totp_secret,
            "codex": codex_result,
            "network_traffic": network_traffic,
            "error": None if codex_ok else f"Codex not completed: {codex_result.get('message')}",
        }
    except Exception as exc:
        if asset_cache is not None and asset_cache_snapshot is None:
            try:
                asset_cache_snapshot = asset_cache.stop()
            except Exception:
                pass
        if traffic_tracker is not None:
            try:
                network_traffic = traffic_tracker.stop()
            except Exception:
                pass
        _merge_proxy_transport_traffic()
        if data_saver is not None:
            data_saver.stop()
        logger.error("[Roxy registration] Failed:%s: %s", type(exc).__name__, exc)
        logger.debug("[Roxy registration] Failure details", exc_info=True)
        # Reclaim the email before creation is confirmed; avoid reuse after confirmation.
        try:
            if email:
                from core.email_provider import release_email
                release_email(email, status="failed" if create_acknowledged else "available", note=f"Roxy registration failed: {str(exc)[:180]}")
        except Exception:
            pass
        return {
            "success": False,
            "email": email,
            "network_traffic": network_traffic,
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
        }
    finally:
        if asset_cache is not None:
            try:
                asset_cache.stop()
            except Exception:
                pass
        if traffic_tracker is not None:
            try:
                traffic_tracker.stop()
            except Exception:
                pass
        if data_saver is not None:
            data_saver.stop()
        if driver and not bool(_cfg.ROXY_KEEP_BROWSER_OPEN):
            try:
                driver.quit()
            except Exception:
                pass
        if not bool(_cfg.ROXY_KEEP_BROWSER_OPEN):
            client.cleanup_profile(opened)
