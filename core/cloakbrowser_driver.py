# -*- coding: utf-8 -*-
"""CloakBrowser Selenium-style lightweight adapter layer."""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from config import cloakbrowser as _cfg

logger = logging.getLogger(__name__)


@dataclass
class CloakOpenResult:
    profile_id: str = "cloakbrowser"
    raw: dict | None = None


class CloakElement:
    def __init__(self, page, locator=None, handle=None):
        self.page = page
        self.locator = locator
        self.handle = handle

    def _handle(self):
        if self.handle is not None:
            return self.handle
        return self.locator.element_handle(timeout=5000)

    def _eval(self, expression: str, arg: Any = None) -> Any:
        if self.locator is not None:
            try:
                return self.locator.evaluate(expression, arg, timeout=3000)
            except TypeError:
                return self.locator.evaluate(expression, arg)
        return self.handle.evaluate(expression, arg)

    def _eval_handle(self, expression: str, arg: Any = None) -> Any:
        h = self._handle()
        return h.evaluate_handle(expression, arg)

    def is_displayed(self) -> bool:
        try:
            if self.locator is not None:
                return bool(self.locator.is_visible(timeout=800))
            return bool(self.handle.evaluate("el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'"))
        except Exception:
            return False

    def is_enabled(self) -> bool:
        try:
            if self.locator is not None:
                return bool(self.locator.is_enabled(timeout=800))
            return bool(self.handle.evaluate("el => !el.disabled && el.getAttribute('aria-disabled') !== 'true'"))
        except Exception:
            return False

    def click(self) -> None:
        if self.locator is not None:
            self.locator.click(timeout=10000)
        else:
            self.handle.click(timeout=10000)

    def clear(self) -> None:
        try:
            if self.locator is not None:
                self.locator.fill("", timeout=10000)
            else:
                self.handle.fill("", timeout=10000)
        except Exception:
            # Some non-input elements do not support fill; fall back to clearing via the keyboard.
            self.click()
            self.page.keyboard.press("Meta+A")
            self.page.keyboard.press("Backspace")

    @property
    def tag_name(self) -> str:
        try:
            return str(self._eval("el => el.tagName.toLowerCase()") or "")
        except Exception:
            return ""

    def send_keys(self, *values: str) -> None:
        # Compatible with Selenium: el.send_keys(Keys.COMMAND, 'a').
        text = "".join(str(v or "") for v in values)
        lower = text.lower()
        try:
            self.click()
        except Exception:
            pass
        if "\ue03d" in text or "\ue009" in text or "command" in lower or "control" in lower:
            # Selenium Keys.CONTROL/COMMAND encoding may pass private-use characters; treat it as select-all here.
            try:
                self.page.keyboard.press("Meta+A")
            except Exception:
                self.page.keyboard.press("Control+A")
            return
        try:
            if self.locator is not None:
                self.locator.fill(text, timeout=10000)
            else:
                self.handle.fill(text, timeout=10000)
        except Exception:
            self.page.keyboard.type(text, delay=35)

    def get_attribute(self, name: str) -> str | None:
        try:
            if self.locator is not None:
                return self.locator.get_attribute(name, timeout=1000)
            return self.handle.get_attribute(name)
        except Exception:
            return None


class _SwitchTo:
    def __init__(self, driver: "CloakSeleniumDriver"):
        self._driver = driver

    def window(self, handle: str) -> None:
        self._driver._switch_window(handle)


class CloakSeleniumDriver:
    """Only implements the subset of WebDriver actually used by this project Roxy Selenium flow."""

    def __init__(self, browser: Any, context: Any | None, page: Any, proxy_relay: Any | None = None):
        self.browser = browser
        self.context = context
        self.page = page
        self._proxy_relay = proxy_relay
        self._page_load_timeout_ms = int(getattr(_cfg, "CLOAK_SELENIUM_TIMEOUT", 90) or 90) * 1000
        self.switch_to = _SwitchTo(self)

    @property
    def current_url(self) -> str:
        return str(getattr(self.page, "url", "") or "")

    @property
    def window_handles(self) -> list[str]:
        pages = self._pages()
        return [str(i) for i in range(len(pages))]

    def _pages(self) -> list[Any]:
        try:
            if self.context is not None:
                return list(self.context.pages)
        except Exception:
            pass
        try:
            contexts = list(getattr(self.browser, "contexts", []) or [])
            pages = []
            for ctx in contexts:
                pages.extend(list(getattr(ctx, "pages", []) or []))
            return pages or [self.page]
        except Exception:
            return [self.page]

    def _switch_window(self, handle: str) -> None:
        pages = self._pages()
        idx = int(handle)
        self.page = pages[idx]
        try:
            self.page.bring_to_front()
        except Exception:
            pass

    def set_page_load_timeout(self, seconds: int) -> None:
        self._page_load_timeout_ms = int(seconds) * 1000
        try:
            self.page.set_default_navigation_timeout(self._page_load_timeout_ms)
            self.page.set_default_timeout(self._page_load_timeout_ms)
        except Exception:
            pass

    def get(self, url: str) -> None:
        self.page.goto(url, wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)

    def back(self) -> None:
        self.page.go_back(wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)

    def refresh(self) -> None:
        self.page.reload(wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)

    def quit(self) -> None:
        try:
            if self.context is not None:
                self.context.close()
        except Exception:
            pass
        try:
            self.browser.close()
        except Exception:
            pass
        relay, self._proxy_relay = self._proxy_relay, None
        if relay is not None:
            relay.close()

    def proxy_transport_snapshot(self) -> dict | None:
        relay = self._proxy_relay
        try:
            return relay.traffic_snapshot() if relay is not None else None
        except Exception:
            return None

    def find_elements(self, by: Any, selector: str) -> list[CloakElement]:
        loc = self._locator(by, selector)
        try:
            count = min(int(loc.count()), 200)
        except Exception:
            count = 0
        return [CloakElement(self.page, loc.nth(i)) for i in range(count)]

    def find_element(self, by: Any, selector: str) -> CloakElement:
        els = self.find_elements(by, selector)
        if not els:
            raise RuntimeError(f"Page element not found: {selector}")
        return els[0]

    def _locator(self, by: Any, selector: str):
        by_s = str(by or "").lower()
        if "xpath" in by_s or str(selector).startswith("//"):
            return self.page.locator(f"xpath={selector}")
        return self.page.locator(selector)

    def execute_script(self, script: str, *args: Any) -> Any:
        return self._evaluate(script, args=args, async_mode=False)

    def execute_async_script(self, script: str, *args: Any) -> Any:
        return self._evaluate(script, args=args, async_mode=True)

    def execute_cdp_cmd(self, cmd: str, params: dict | None = None) -> Any:
        params = params or {}
        try:
            client = self.context.new_cdp_session(self.page) if self.context is not None else self.page.context.new_cdp_session(self.page)
            return client.send(cmd, params)
        except Exception as exc:
            logger.debug("[Cloak] CDP command failed %s: %s", cmd, exc)
            return None

    def _serialize_args(self, args: tuple[Any, ...]) -> tuple[CloakElement | None, list[Any]]:
        """Split Selenium script arguments.

        Playwright JSHandle/ElementHandle cannot be reliably nested in dict/list payloads passed across
        page.evaluate calls; the most common Selenium script pattern is `arguments[0]` being the element,
        so here the first CloakElement is passed in as the real DOM `el`, and the other arguments stay
        JSON serializable.
        """
        first_el = args[0] if args and isinstance(args[0], CloakElement) else None
        rest = list(args[1:] if first_el else args)
        cleaned = []
        for item in rest:
            if isinstance(item, CloakElement):
                # In rare cases a script passes multiple elements; using the real handle directly would break inside a nested payload,
                # so it degrades to None here, which is safer than passing a wrong object into JS.
                cleaned.append(None)
            else:
                cleaned.append(item)
        return first_el, cleaned

    @staticmethod
    def _unwrap_js_result(page, handle: Any) -> Any:
        try:
            element = handle.as_element()
        except Exception:
            element = None
        if element is not None:
            return CloakElement(page, handle=element)
        try:
            return handle.json_value()
        except Exception as exc:
            msg = str(exc)
            if "Execution context was destroyed" in msg or "navigation" in msg.lower():
                logger.info("[Cloak] JS page navigated after execution, ignoring the failure to read the return value:%s", msg[:160])
                return {"ok": True, "reason": "navigation_after_script"}
            raise
        finally:
            try:
                handle.dispose()
            except Exception:
                pass

    def _evaluate(self, script: str, args: tuple[Any, ...], async_mode: bool) -> Any:
        first_el, serial_args = self._serialize_args(args)
        if async_mode:
            wrapper = """async ({script, args}) => {
              return await new Promise((resolve) => {
                const fn = new Function(...args.map((_, i) => 'a' + i), '__cloak_done', script);
                const timer = setTimeout(() => resolve({__cloak_timeout:true}), 120000);
                const __cloak_done = (v) => { clearTimeout(timer); resolve(v); };
                try { fn(...args, __cloak_done); } catch (e) { clearTimeout(timer); resolve({ok:false, error:String(e)}); }
              });
            }"""
            element_wrapper = """async (el, payload) => {
              const args = [el, ...payload.args];
              return await new Promise((resolve) => {
                const fn = new Function(...args.map((_, i) => 'a' + i), '__cloak_done', payload.script);
                const timer = setTimeout(() => resolve({__cloak_timeout:true}), 120000);
                const __cloak_done = (v) => { clearTimeout(timer); resolve(v); };
                try { fn(...args, __cloak_done); } catch (e) { clearTimeout(timer); resolve({ok:false, error:String(e)}); }
              });
            }"""
            if first_el is not None:
                result = first_el._eval(element_wrapper, {"script": script, "args": serial_args})
            else:
                result = self.page.evaluate(wrapper, {"script": script, "args": serial_args})
            if isinstance(result, dict) and result.get("__cloak_timeout"):
                raise TimeoutError("execute_async_script timeout")
            return result

        # Selenium scripts are often built around `return ...`; use Function to preserve semantics.
        wrapper = """({script, args}) => {
          const fn = new Function(...args.map((_, i) => 'a' + i), script);
          return fn(...args);
        }"""
        element_wrapper = """(el, payload) => {
          const args = [el, ...payload.args];
          const fn = new Function(...args.map((_, i) => 'a' + i), payload.script);
          return fn(...args);
        }"""
        if first_el is not None:
            handle = first_el._eval_handle(element_wrapper, {"script": script, "args": serial_args})
        else:
            handle = self.page.evaluate_handle(wrapper, {"script": script, "args": serial_args})
        return self._unwrap_js_result(self.page, handle)


def _normalize_proxy(proxy: str | None) -> str | None:
    proxy = str(proxy or "").strip()
    if not proxy:
        return None
    return proxy.replace("socks5h://", "socks5://")


def _detect_cloak_exit_geo(proxy_url: str | None = None) -> dict:
    """Detect geo info from the current/proxy egress, for explicit Cloak locale/timezone use."""
    try:
        import requests
        from config import browser as _browser_cfg
        endpoints = list(getattr(_browser_cfg, "IP_GEO_ENDPOINTS", []) or [])
        timeout = float(getattr(_browser_cfg, "IP_GEO_TIMEOUT", 6) or 6)
    except Exception:
        return {}
    proxies = None
    if proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    for url in endpoints:
        try:
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            if resp.status_code != 200:
                continue
            data = resp.json()
            timezone = data.get("timezone")
            if isinstance(timezone, dict):
                timezone = timezone.get("id") or timezone.get("name")
            geo = {
                "ip": data.get("ip") or data.get("query"),
                "country": (data.get("country") or data.get("country_code") or data.get("countryCode") or "").upper(),
                "region": data.get("region") or data.get("regionName"),
                "city": data.get("city"),
                "timezone": timezone or "",
                "org": data.get("org") or data.get("isp") or (data.get("connection") or {}).get("org"),
            }
            if geo.get("country") or geo.get("timezone"):
                logger.info(
                    "[Cloak] Egress IP geo info:ip=%s country=%s city=%s timezone=%s",
                    geo.get("ip") or "?", geo.get("country") or "?", geo.get("city") or "?", geo.get("timezone") or "?",
                )
                return geo
        except Exception as exc:
            logger.debug("[Cloak] Egress IP geo detection failed endpoint=%s: %s: %s", url, type(exc).__name__, exc)
    return {}


def _build_cloak_locale_options(proxy_url: str | None = None) -> dict:
    """Generate the dual-layer Cloak/Playwright language and timezone config."""
    explicit_locale = str(getattr(_cfg, "CLOAK_LOCALE", "") or "").strip()
    explicit_timezone = str(getattr(_cfg, "CLOAK_TIMEZONE", "") or "").strip()
    out = {}
    if explicit_locale:
        out["locale"] = explicit_locale
        # Accept-Language is more complete when inferred automatically from config.browser; when explicit, give a conservative value.
        out["accept_language"] = f"{explicit_locale},{explicit_locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7"
    if explicit_timezone:
        out["timezone"] = explicit_timezone
    if explicit_locale and explicit_timezone:
        return out
    if not bool(getattr(_cfg, "CLOAK_GEOIP", True)):
        return out
    try:
        from config.browser import build_browser_environment
        geo = _detect_cloak_exit_geo(proxy_url)
        profile = build_browser_environment(geo)
        out.setdefault("locale", str(profile.get("navigator_language") or ""))
        out.setdefault("timezone", str(profile.get("timezone_iana") or ""))
        out.setdefault("accept_language", str(profile.get("accept_language") or ""))
        out["geo"] = geo
    except Exception as exc:
        logger.debug("[Cloak] Failed to build auto language/timezone:%s: %s", type(exc).__name__, exc)
    return {k: v for k, v in out.items() if v}


def build_cloak_driver(proxy: str | None = None) -> tuple[CloakSeleniumDriver, CloakOpenResult]:
    """Launch CloakBrowser and return a Selenium-style driver.

    proxy=None  picks a random proxy from config.proxy.PROXY_POOL;
    proxy=""    explicitly disables the proxy;
    proxy="..." uses the specified proxy.
    """
    proxy_relay = None
    proxy_pool_target = ""
    if proxy is None and bool(getattr(_cfg, "CLOAK_USE_PROXY", True)):
        try:
            from config.proxy import pick_proxy
        except Exception:
            proxy = None
        else:
            from core.proxy_chain import open_proxy_pool_proxy
            proxy_pool_target = str(pick_proxy() or "").strip()
            proxy, proxy_relay = open_proxy_pool_proxy(proxy_pool_target, measure_transport=True)
    elif proxy and bool(getattr(_cfg, "CLOAK_USE_PROXY", True)):
        from core.proxy_chain import ProxyChainRelay, browser_blocked_proxy_hosts
        from core.proxy_utils import parse_proxy_url
        proxy_pool_target = proxy
        if parse_proxy_url(proxy).scheme in {"http", "socks5", "socks5h"}:
            proxy_relay = ProxyChainRelay(proxy, blocked_hosts=browser_blocked_proxy_hosts()).start()
            proxy = proxy_relay.proxy_url
    try:
        from cloakbrowser import launch, launch_persistent_context
    except ImportError as exc:
        raise RuntimeError("cloakbrowser is not installed, please run:pip install cloakbrowser") from exc

    launch_args = list(getattr(_cfg, "CLOAK_EXTRA_ARGS", []) or [])
    seed = str(getattr(_cfg, "CLOAK_FINGERPRINT_SEED", "") or "").strip()
    if seed:
        launch_args.append(f"--fingerprint={seed}")

    proxy_url = _normalize_proxy(proxy) if bool(getattr(_cfg, "CLOAK_USE_PROXY", True)) else None
    locale_opts = _build_cloak_locale_options(proxy_url)
    # geoip=True lets CloakBrowser automatically match timezone/locale/WebRTC to the current egress IP.
    # Previously it was enabled only with an explicit proxy_url; if the user goes through a system proxy/VPN/transparent proxy, at the code level
    # proxy_url is not visible, so geoip would be wrongly disabled and the language/timezone would not follow the egress. Now the config is fully respected.
    opts = {
        "headless": bool(getattr(_cfg, "CLOAK_HEADLESS", False)),
        "humanize": bool(getattr(_cfg, "CLOAK_HUMANIZE", True)),
        "geoip": bool(getattr(_cfg, "CLOAK_GEOIP", True)),
    }
    if locale_opts.get("locale"):
        opts["locale"] = locale_opts["locale"]
    if locale_opts.get("timezone"):
        opts["timezone"] = locale_opts["timezone"]
    if proxy_url:
        opts["proxy"] = proxy_url
    if launch_args:
        opts["args"] = launch_args
    license_key = str(getattr(_cfg, "CLOAK_LICENSE_KEY", "") or "").strip()
    if license_key:
        opts["license_key"] = license_key

    user_data_dir = str(getattr(_cfg, "CLOAK_USER_DATA_DIR", "") or "").strip()
    logger.info(
        "[Cloak] Launching CloakBrowser:headless=%s humanize=%s geoip=%s proxy=%s locale=%s timezone=%s accept_language=%s persistent=%s",
        opts.get("headless"), opts.get("humanize"), opts.get("geoip"),
        proxy_url or "none", opts.get("locale") or "auto/default", opts.get("timezone") or "auto/default",
        locale_opts.get("accept_language") or "auto/default", bool(user_data_dir),
    )
    context_kwargs = {}
    if locale_opts.get("locale"):
        context_kwargs["locale"] = locale_opts["locale"]
    if locale_opts.get("timezone"):
        context_kwargs["timezone_id"] = locale_opts["timezone"]
    if locale_opts.get("accept_language"):
        context_kwargs["extra_http_headers"] = {"Accept-Language": locale_opts["accept_language"]}

    if user_data_dir:
        context = launch_persistent_context(user_data_dir, **opts)
        page = context.new_page()
        browser = getattr(context, "browser", None) or context
        # persistent context locale/timezone are already passed in via the launch_persistent_context arguments.
    else:
        browser = launch(**opts)
        context = browser.new_context(**context_kwargs)
        page = context.new_page()

    driver = CloakSeleniumDriver(browser=browser, context=context, page=page, proxy_relay=proxy_relay)
    # Roxy/Cloak share some page operation functions; give the shared functions an explicit log prefix,
    # to avoid `[Roxy registration]` appearing in the Cloak registration flow.
    driver._registration_log_prefix = "[Cloak registration]"
    driver.set_page_load_timeout(int(getattr(_cfg, "CLOAK_SELENIUM_TIMEOUT", 90) or 90))
    return driver, CloakOpenResult(raw={
        "driver": "cloakbrowser",
        "proxy": proxy_url,
        "proxy_pool_target": proxy_pool_target or proxy_url,
        "locale": locale_opts,
        "options": {k: v for k, v in opts.items() if k != "license_key"},
    })
