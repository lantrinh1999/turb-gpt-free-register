# -*- coding: utf-8 -*-
"""Traffic-saving resource blocking for the browser registration flow.

Traffic-saving mode only blocks optional page resources in the local Roxy/Cloak fingerprint browsers and those explicitly specified in the config
URL; by default it does not block the document / core script / stylesheet / xhr / fetch / websocket, so login,
verification codes and session writes are not affected. Playwright can block precisely by resource type and URL glob;Selenium/Roxy
Chrome CDP URL globs are used to block resources with common extensions and configured URLs.Browser Use/Skyvern
Cloud browsers do not install the interceptor of this module.
"""
from __future__ import annotations

import logging
import threading
from collections import Counter
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit

from config import browser as _cfg

logger = logging.getLogger(__name__)


# Playwright Request.resource_type enum. The common types are kept here; unknown values do not make
# the registration flow fail; users can fill in several values in the config, one per line.
_RESOURCE_TYPE_ALIASES = {
    "images": "image",
    "img": "image",
    "videos": "media",
    "video": "media",
    "audio": "media",
    "fonts": "font",
    "tracks": "texttrack",
    "track": "texttrack",
}
_KNOWN_RESOURCE_TYPES = {
    "document",
    "stylesheet",
    "image",
    "media",
    "font",
    "script",
    "texttrack",
    "xhr",
    "fetch",
    "eventsource",
    "websocket",
    "manifest",
    "other",
}

# Selenium/CDP does not expose a resourceType filter through Network.setBlockedURLs, so blocking can only be done by
# URL glob filtering. Therefore only common static resource suffixes are listed, and the whole third-party domain is not blocked.
_URL_EXTENSIONS_BY_TYPE = {
    "image": (
        ".apng", ".avif", ".bmp", ".gif", ".ico", ".jfif", ".jpeg", ".jpg",
        ".png", ".svg", ".webp",
    ),
    "media": (
        ".3gp", ".avi", ".flac", ".m4a", ".m4v", ".mkv", ".mov", ".mp3",
        ".mp4", ".mpeg", ".ogg", ".wav", ".webm",
    ),
    "font": (".eot", ".otf", ".ttf", ".woff", ".woff2"),
    "manifest": (".webmanifest", "/manifest.json"),
    "texttrack": (".vtt", ".srt"),
    # The following kinds are not defaults but may be used in advanced configuration; before enabling, confirm the page does not depend on them.
    "stylesheet": (".css",),
    "script": (".js", ".mjs"),
}

# Login risk control / verification challenges may label captcha images and challenge resources as image. The Playwright route
# can let these resources through by URL exception; the URL blacklist of Selenium/CDP has no exception rule and can only rely on
# such resources usually do not use common static suffixes; when a captcha misbehaves, turn the mode off to investigate.
_CHALLENGE_KEYWORDS = (
    "captcha", "challenge", "arkose", "hcaptcha", "recaptcha", "turnstile",
    "verification", "verify",
)


def _as_items(value: Any, *, lower: bool = True) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.replace(",", "\n").splitlines()
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = [value]
    result = [str(item or "").strip() for item in raw if str(item or "").strip()]
    return [item.lower() for item in result] if lower else result


def configured_resource_types() -> list[str]:
    """Read and normalize the traffic-saving block types; invalid types are ignored."""
    raw = getattr(_cfg, "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", ("image", "media"))
    result: list[str] = []
    for item in _as_items(raw, lower=True):
        item = _RESOURCE_TYPE_ALIASES.get(item, item)
        if item in _KNOWN_RESOURCE_TYPES and item not in result:
            result.append(item)
    return result


def configured_url_patterns() -> list[str]:
    """Read and normalize the extra URL glob rules; empty items are removed and duplicates dropped, keeping the configured order."""
    raw = getattr(_cfg, "BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS", ())
    result: list[str] = []
    # URL path may be case-sensitive, so it cannot be lowercased uniformly like resource_type.
    for item in _as_items(raw, lower=False):
        if item not in result:
            result.append(item)
    return result


def _is_challenge_url(url: str) -> bool:
    lower = str(url or "").lower()
    return any(keyword in lower for keyword in _CHALLENGE_KEYWORDS)


def _infer_resource_type(url: str) -> str:
    """Selenium When a CDP event lacks type, infer conservatively from the URL suffix."""
    try:
        path = urlsplit(str(url or "")).path.lower()
    except Exception:
        path = str(url or "").lower().split("?", 1)[0].split("#", 1)[0]
    for resource_type, extensions in _URL_EXTENSIONS_BY_TYPE.items():
        if any(path.endswith(extension) for extension in extensions):
            return resource_type
    return "other"


class BrowserDataSaver:
    """Install the optional resource interceptor for one browser session."""

    def __init__(self, *, label: str = "Browser"):
        self.label = str(label or "Browser")
        self.enabled = bool(getattr(_cfg, "BROWSER_DATA_SAVER_MODE", False))
        self.resource_types = configured_resource_types() if self.enabled else []
        self.url_patterns = configured_url_patterns() if self.enabled else []
        self.blocked_count = 0
        self.blocked_by_type: Counter[str] = Counter()
        self.blocked_by_url_pattern: Counter[str] = Counter()
        self._lock = threading.RLock()
        self._context: Any | None = None
        self._driver: Any | None = None
        self._route_handler: Any | None = None
        self._blocked_playwright_requests: set[int] = set()
        self._selenium_patterns: list[str] = []
        self._installed = False
        self._stopped = False
        self.method = "disabled"

    def _matching_url_pattern(self, url: str) -> str | None:
        """Return the first matching URL glob; the rule match is case-sensitive on the original URL text."""
        text = str(url or "")
        if not text:
            return None
        for pattern in self.url_patterns:
            try:
                if fnmatchcase(text, pattern):
                    return pattern
            except Exception:
                continue
        return None

    def _should_block(self, resource_type: str, url: str) -> bool:
        if not self.enabled or self._stopped:
            return False
        resource_type = _RESOURCE_TYPE_ALIASES.get(str(resource_type or "").lower(), str(resource_type or "").lower())
        matched_url_pattern = self._matching_url_pattern(url)
        if resource_type not in self.resource_types and matched_url_pattern is None:
            return False
        # Verification challenge resources are let through first; normal page images/media are still blocked.
        if _is_challenge_url(url):
            return False
        return True

    def _record_blocked(
        self,
        resource_type: str,
        *,
        request: Any | None = None,
        url_pattern: str | None = None,
    ) -> None:
        normalized = _RESOURCE_TYPE_ALIASES.get(str(resource_type or "other").lower(), str(resource_type or "other").lower())
        with self._lock:
            self.blocked_count += 1
            self.blocked_by_type[normalized or "other"] += 1
            if url_pattern:
                self.blocked_by_url_pattern[str(url_pattern)] += 1
            if request is not None:
                self._blocked_playwright_requests.add(id(request))

    def was_playwright_blocked(self, request: Any) -> bool:
        """Lets the Playwright traffic counter exclude the fake upload bytes produced by route.abort()."""
        with self._lock:
            key = id(request)
            if key not in self._blocked_playwright_requests:
                return False
            self._blocked_playwright_requests.remove(key)
            return True

    def install_playwright(self, context: Any) -> "BrowserDataSaver":
        """Block requests on the BrowserContext by resource_type."""
        if not self.enabled:
            return self
        if not self.resource_types and not self.url_patterns:
            logger.info("[%s] Traffic-saving mode is on, but no blockable resource types or URL rules are configured", self.label)
            return self
        try:
            def _handle_route(route: Any) -> None:
                try:
                    request = route.request
                    resource_type = getattr(request, "resource_type", "")
                    url = getattr(request, "url", "")
                    if self._should_block(resource_type, url):
                        self._record_blocked(
                            resource_type,
                            request=request,
                            url_pattern=self._matching_url_pattern(url),
                        )
                        try:
                            route.abort("blockedbyclient")
                        except TypeError:
                            # Compatible with the very old Playwright route.abort() signature.
                            route.abort()
                        return
                    route.continue_()
                except Exception as exc:
                    # The interceptor must not break the main registration flow; on exceptions let the request through as far as possible.
                    logger.debug("[%s] Traffic-saving route handling failed, trying to let it through:%s", self.label, exc)
                    try:
                        route.continue_()
                    except Exception:
                        pass

            context.route("**/*", _handle_route)
            self._context = context
            self._route_handler = _handle_route
            self._installed = True
            self.method = "playwright.context.route"
            logger.info(
                "[%s] Traffic-saving mode enabled: blocked resource types=%s, URL rules=%s (captcha/challenge related URLs are let through)",
                self.label,
                ",".join(self.resource_types) or "-",
                len(self.url_patterns),
            )
        except Exception as exc:
            logger.warning("[%s] Failed to install the Playwright traffic-saving interception, continuing without blocking:%s: %s", self.label, type(exc).__name__, exc)
        return self

    def install_selenium(self, driver: Any) -> "BrowserDataSaver":
        """Install URL suffix and URL glob blocking through Chrome CDP Network.setBlockedURLs."""
        if not self.enabled:
            return self
        patterns: list[str] = []
        for resource_type in self.resource_types:
            for extension in _URL_EXTENSIONS_BY_TYPE.get(resource_type, ()):
                # Omit scheme/host so that similar resource URLs with query/hash match.
                patterns.append(f"*{extension}*")
        # CDP URL matcher uses * as the wildcard; the one in the Playwright rule **
        # is narrowed to a single *, which makes cross-path URL matching in CDP work.
        patterns.extend(pattern.replace("**", "*") for pattern in self.url_patterns)
        # Deduplicate and keep the config/extension order, so logs and tests stay stable.
        patterns = list(dict.fromkeys(patterns))
        if not patterns:
            logger.info("[%s] Traffic-saving mode is on, but Selenium has no usable URL rules", self.label)
            return self
        try:
            # In some cases the traffic counter was not initialized successfully, so the Network domain still has to be enabled separately.
            try:
                driver.execute_cdp_cmd("Network.enable", {})
            except Exception:
                pass
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": patterns})
            self._driver = driver
            self._selenium_patterns = patterns
            self._installed = True
            self.method = "selenium.cdp.Network.setBlockedURLs"
            logger.info(
                "[%s] Traffic-saving mode enabled: blocking by URL, resource types=%s, type rules=%s, URL rules=%s (Selenium URL rules do not support challenge exceptions)",
                self.label,
                ",".join(self.resource_types) or "-",
                sum(len(_URL_EXTENSIONS_BY_TYPE.get(resource_type, ())) for resource_type in self.resource_types),
                len(self.url_patterns),
            )
        except Exception as exc:
            logger.warning("[%s] Failed to install the Selenium traffic-saving interception, continuing without blocking:%s: %s", self.label, type(exc).__name__, exc)
        return self

    def enable_post_auth_deep_mode(self, driver: Any) -> bool:
        """Tighten the rules after registration completes to block app-shell and telemetry requests that are no longer needed."""
        if not self.enabled or not bool(getattr(_cfg, "BROWSER_DATA_SAVER_DEEP_MODE", True)):
            return False
        patterns = [
            "*://chatgpt.com/_next/*", "*://www.chatgpt.com/_next/*",
            "*://chatgpt.com/cdn/assets/*", "*://www.chatgpt.com/cdn/assets/*",
            "*://chatgpt.com/unauth-mweb/*", "*://www.chatgpt.com/unauth-mweb/*",
            "*://oaistatic.com/*", "*://*.oaistatic.com/*",
            "*://chatgpt.com/ces/*", "*://www.chatgpt.com/ces/*",
            "*://auth.openai.com/awe/api/v2/rum*", "*://chatgpt.com/awe/api/v2/rum*",
        ]
        patterns = list(dict.fromkeys(self._selenium_patterns + patterns))
        try:
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": patterns})
            self._selenium_patterns = patterns
            logger.info("[%s] Post-registration deep traffic saving enabled: app-shell/telemetry rules=%s", self.label, len(patterns))
            return True
        except Exception as exc:
            logger.warning("[%s] Failed to install post-registration deep traffic saving, staying online:%s", self.label, str(exc)[:180])
            return False

    def observe_cdp_event(self, method: str, params: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        """Let the Selenium traffic counter recognize the CDP inspector blocking events.

        Returning True means this request was blocked by the traffic-saving rules; the counter should skip estimating its request headers,
        because the request was never actually sent to the network.
        """
        if not self.enabled or method != "Network.loadingFailed":
            return False
        if str(params.get("blockedReason") or "").lower() != "inspector":
            return False
        request = request or {}
        url = str(request.get("url") or "")
        resource_type = str(request.get("resourceType") or "").strip().lower() or _infer_resource_type(url)
        resource_type = _RESOURCE_TYPE_ALIASES.get(resource_type, resource_type)
        if self._selenium_patterns:
            if not url or not any(fnmatchcase(url, pattern) for pattern in self._selenium_patterns):
                return False
        # Keeps resource-type event compatibility when install_selenium() was not called; after a normal successful install
        # there are always URL rules, which take the exact branch above.
        elif resource_type not in self.resource_types:
            return False
        self._record_blocked(resource_type, url_pattern=self._matching_url_pattern(url))
        return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "data_saver_enabled": bool(self.enabled),
                "data_saver_method": self.method,
                "data_saver_blocked_resource_types": list(self.resource_types),
                "data_saver_blocked_url_patterns": list(self.url_patterns),
                "data_saver_blocked_count": int(self.blocked_count),
                "data_saver_blocked_by_type": dict(sorted(self.blocked_by_type.items())),
                "data_saver_blocked_by_url_pattern": dict(sorted(self.blocked_by_url_pattern.items())),
            }

    def stop(self) -> None:
        """Remove the Playwright route; the CDP URL rules end with the browser session."""
        if self._stopped:
            return
        self._stopped = True
        if self._context is not None and self._route_handler is not None:
            try:
                self._context.unroute("**/*", self._route_handler)
            except Exception:
                pass
        self._route_handler = None
        self._context = None
        self._driver = None
        self._blocked_playwright_requests.clear()


__all__ = ["BrowserDataSaver", "configured_resource_types", "configured_url_patterns"]
