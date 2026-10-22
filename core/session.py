# -*- coding: utf-8 -*-
"""
curl_cffi Session wrapper
Uniformly manages Cookies, request headers and the TLS fingerprint
"""
import logging
import hashlib
import random
import re
import threading
import time
import uuid
from urllib.parse import urlparse
from curl_cffi.requests import Session

from config import (
    USER_AGENT, SEC_CH_UA, SEC_CH_UA_PLATFORM, SEC_CH_UA_MOBILE,
    SEC_CH_UA_FULL_VERSION_LIST, SEC_CH_UA_PLATFORM_VERSION, SEC_CH_UA_ARCH,
    SEC_CH_UA_BITNESS, SEC_CH_UA_MODEL, SEND_HIGH_ENTROPY_CLIENT_HINTS,
    ACCEPT_LANGUAGE, IMPERSONATE, OAI_CLIENT_BUILD_NUMBER, OAI_CLIENT_VERSION,
    REQUEST_TIMEOUT, pick_proxy, pick_browser_profile, validate_browser_profile,
    BROWSER_PROFILE_POOL, build_browser_environment,
)


logger = logging.getLogger(__name__)
_GEO_CACHE: dict[str, dict] = {}
_GEO_CACHE_LOCK = threading.Lock()
_CF_COOKIE_NAMES = ("cf_clearance", "__cf_bm", "__cfseq", "cf_chl_rc_i", "cf_chl_rc_ni", "cf_chl_rc_m")
_COUNTRY_NAME_TO_CODE = {
    "JAPAN": "JP", "CHINA": "CN", "UNITED STATES": "US", "UNITED STATES OF AMERICA": "US",
    "UNITED KINGDOM": "GB", "GREAT BRITAIN": "GB", "VIETNAM": "VN", "VIET NAM": "VN",
    "THAILAND": "TH", "SINGAPORE": "SG", "HONG KONG": "HK", "TAIWAN": "TW",
    "SOUTH KOREA": "KR", "REPUBLIC OF KOREA": "KR", "INDONESIA": "ID", "MALAYSIA": "MY",
    "PHILIPPINES": "PH", "INDIA": "IN", "AUSTRALIA": "AU", "CANADA": "CA",
    "GERMANY": "DE", "FRANCE": "FR", "NETHERLANDS": "NL", "BRAZIL": "BR",
}


def close_browser_session(session) -> None:
    """Close a BrowserSession while retaining compatibility with test doubles."""
    if session is None:
        return
    close = getattr(type(session), "close", None)
    if callable(close):
        close(session)
        return
    raw_session = getattr(session, "session", None)
    if raw_session is not None:
        raw_session.close()


def _seed_uuid(seed: str, salt: str) -> str:
    text = f"{salt}:{seed}".strip()
    return str(uuid.uuid5(uuid.NAMESPACE_URL, text))


def _seed_int(seed: str, salt: str, *, bits: int = 63) -> int:
    digest = hashlib.sha256(f"{salt}:{seed}".encode("utf-8")).digest()
    nbytes = max(1, (bits + 7) // 8)
    value = int.from_bytes(digest[:nbytes], "big")
    mask = (1 << bits) - 1
    return value & mask


def _seeded_browser_profile(seed: str, geo: dict | None = None) -> dict:
    if not seed:
        return pick_browser_profile(geo)
    pool = list(BROWSER_PROFILE_POOL or [])
    if not pool:
        return pick_browser_profile(geo)
    idx = _seed_int(seed, "browser_profile_index", bits=32) % len(pool)
    return build_browser_environment(geo, base_profile=pool[idx])


class BrowserSession:
    """
    HTTP session manager that simulates a Chrome browser.
    Uses the impersonate feature of curl_cffi to get around the Cloudflare TLS fingerprint detection.
    """

    def __init__(
        self,
        proxy: str = None,
        *,
        detect_exit_geo: bool = True,
        device_id: str | None = None,
        auth_session_logging_id: str | None = None,
        oai_session_id: str | None = None,
        sentinel_sid: str | None = None,
        browser_profile: dict | None = None,
        fingerprint_seed: str | None = None,
    ):
        """
        Initialize the session.

        Args:
            proxy: Proxy address, such as "socks5h://user:pass@host:port".
                   When not passed, one is drawn from config.PROXY_POOL at random.
                   Passing "" explicitly disables the proxy.
            detect_exit_geo: Whether to probe the exit IP and automatically pick the language/timezone profile.
                             Short requests such as plan checks may turn it off, to avoid extra network waiting.
        """
        # proxy=None  → Draw randomly from the pool (default behavior), and decide whether to chain according to the proxy-pool upstream config
        # proxy=""    → disable the proxy (direct connection)
        # proxy="..." → Use the specified proxy, without applying the proxy-pool upstream
        self._proxy_pool_relay = None
        if proxy is None:
            self.proxy = pick_proxy()
            self.proxy_target = self.proxy
            if self.proxy:
                from core.proxy_chain import open_proxy_pool_proxy
                transport_proxy, self._proxy_pool_relay = open_proxy_pool_proxy(self.proxy)
            else:
                transport_proxy = ""
        else:
            self.proxy = proxy
            self.proxy_target = proxy
            transport_proxy = proxy

        self.fingerprint_seed = str(fingerprint_seed or "").strip()

        # Generate/reuse the device ID (oai-did), reused for the whole task lifecycle.
        if device_id:
            self.device_id = str(device_id)
        elif self.fingerprint_seed:
            self.device_id = _seed_uuid(self.fingerprint_seed, "device_id")
        else:
            self.device_id = str(uuid.uuid4())

        # Generate auth_session_logging_id
        if auth_session_logging_id:
            self.auth_session_logging_id = str(auth_session_logging_id)
        elif self.fingerprint_seed:
            self.auth_session_logging_id = _seed_uuid(self.fingerprint_seed, "auth_session_logging_id")
        else:
            self.auth_session_logging_id = str(uuid.uuid4())

        # Auth Web Reuse this ID within the same document; rotate it when a real page navigation happens.
        self.document_navigation_id = str(uuid.uuid4())

        # ChatGPT Front-end session ID: stays stable within the CES / Statsig / API chains.
        if oai_session_id:
            self.oai_session_id = str(oai_session_id)
        elif self.fingerprint_seed:
            self.oai_session_id = _seed_uuid(self.fingerprint_seed, "oai_session_id")
        else:
            self.oai_session_id = str(uuid.uuid4())

        # Datadog/RUM Correlation ID: generated independently for every BrowserSession, and must never be reused across accounts.
        # The runtime environment of the same account is kept as fixed as possible, to avoid fingerprint drift across several operations of the same account.
        if self.fingerprint_seed:
            self.datadog_trace_id = str(_seed_int(self.fingerprint_seed, "datadog_trace_id"))
            self.datadog_parent_id = str(_seed_int(self.fingerprint_seed, "datadog_parent_id"))
        else:
            self.datadog_trace_id = str(random.getrandbits(63))
            self.datadog_parent_id = str(random.getrandbits(63))
        self.datadog_origin = "rum"
        # Use the config defaults first, and after loading the real ChatGPT login page, take data-build/data-seq
        # dynamic sync, to avoid continuing to send an outdated front-end version header during a rolling release.
        self.client_build_number = str(OAI_CLIENT_BUILD_NUMBER)
        self.client_version = str(OAI_CLIENT_VERSION)

        # Sentinel SDK Internal sid: the real SDK generates a separate UUID, which is not the same value as oai-did.
        # Python The initial p and the final token of the Node Runner both reuse this sid, keeping the semantics of one SDK instance.
        if sentinel_sid:
            self.sentinel_sid = str(sentinel_sid)
        elif self.fingerprint_seed:
            self.sentinel_sid = _seed_uuid(self.fingerprint_seed, "sentinel_sid")
        else:
            self.sentinel_sid = str(uuid.uuid4())
        # The password registration iframe and the top-level Auth page are two independent Sentinel SDK instances.
        if self.fingerprint_seed:
            self.sentinel_iframe_sid = _seed_uuid(self.fingerprint_seed, "sentinel_iframe_sid")
        else:
            self.sentinel_iframe_sid = str(uuid.uuid4())
        if self.fingerprint_seed:
            self.react_listening_key = "_reactListening" + _seed_uuid(self.fingerprint_seed, "react_listening_key").replace("-", "")[:12]
            self.react_container_key = "__reactContainer$" + _seed_uuid(self.fingerprint_seed, "react_container_key").replace("-", "")[:11]
        else:
            self.react_listening_key = "_reactListening" + uuid.uuid4().hex[:12]
            self.react_container_key = "__reactContainer$" + uuid.uuid4().hex[:11]
        self.react_resources_key = "__reactResources$" + self.react_container_key.split("$", 1)[1]

        # Create the curl_cffi session
        self.session = Session(impersonate=IMPERSONATE)

        # Set the proxy
        if transport_proxy:
            self.session.proxies = {
                "http": transport_proxy,
                "https": transport_proxy,
            }

        # Set the timeouts
        self.session.timeout = REQUEST_TIMEOUT

        # Session-level circuit breaker: after a 403/429, stop calling the following endpoints, to avoid widening the collateral damage in an abnormal state.
        self.blocked_until = 0.0
        self.blocked_reason = ""

        # First detect the exit IP geo information with the current proxy, then pick a stable browser profile for this session.
        # This way Accept-Language / navigator.language / timezone can follow the exit region automatically.
        self.exit_geo = self._detect_exit_geo() if detect_exit_geo else {}
        self._enforce_proxy_quality()
        if browser_profile:
            self.browser_profile = dict(browser_profile)
        else:
            self.browser_profile = dict(_seeded_browser_profile(self.fingerprint_seed, self.exit_geo))
        self.browser_profile["react_listening_key"] = self.react_listening_key
        self.browser_profile["react_container_key"] = self.react_container_key
        self.browser_profile["react_resources_key"] = self.react_resources_key
        issues = validate_browser_profile(self.browser_profile)
        if issues:
            logger.warning("[fingerprint] The browser profile is inconsistent: %s", "; ".join(issues))

        # Make the HTTP Cookie, the OAuth parameter ext-oai-did and the id in Sentinel consistent.
        # In a browser oai-did usually exists as a first-party Cookie; filling it in at the protocol layer reduces the inconsistency within one session of
        # “headers/parameters/JS fingerprint having a device ID while the Cookie Jar is empty.
        for domain in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
            self.session.cookies.set("oai-did", self.device_id, domain=domain, path="/")
        # Following the real front-end session: the language is not only reflected in Accept-Language/oai-language, but also written into
        # the same Cookie Jar, to avoid the proxy being JP while the Cookie still leaks the default region.
        locale = self.navigator_language()
        for domain in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
            self.session.cookies.set("oai-locale", locale, domain=domain, path="/")

        # Cloudflare The state can only come from the Set-Cookie of real responses; here changes are only recorded, never forged/overwritten.
        self._cf_cookie_seen = self.cf_cookie_snapshot()

    def cf_cookie_snapshot(self) -> dict:
        """Return a summary of the key Cloudflare Cookies in the current CookieJar, to confirm same-IP/same-session continuity."""
        out = {}
        try:
            for cookie in self.session.cookies.jar:
                name = getattr(cookie, "name", "")
                if name in _CF_COOKIE_NAMES:
                    out[f"{getattr(cookie, 'domain', '')}:{name}"] = len(str(getattr(cookie, "value", "") or ""))
        except Exception:
            pass
        return out

    def close(self) -> None:
        """Close the HTTP session and any proxy-pool relay owned by this session."""
        try:
            self.session.close()
        finally:
            relay, self._proxy_pool_relay = self._proxy_pool_relay, None
            if relay is not None:
                relay.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @staticmethod
    def _short_value(value: object, limit: int = 80) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return text if len(text) <= limit else text[: max(0, limit - 3)] + "..."

    def fingerprint_summary(self) -> dict:
        """Return a browser fingerprint summary suitable for logging/persisting, without expanding overly long array fields."""
        profile = getattr(self, "browser_profile", {}) or {}
        geo = profile.get("geo") or self.exit_geo or {}
        summary = {
            "device_id": self.device_id,
            "proxy": self.proxy or "",
            "proxy_mode": "direct" if not self.proxy else "proxy",
            "browser_family": profile.get("browser_family") or "chrome",
            "browser_os": profile.get("browser_os") or "macOS",
            "user_agent": profile.get("user_agent") or USER_AGENT,
            "accept_language": profile.get("accept_language") or ACCEPT_LANGUAGE,
            "navigator_language": profile.get("navigator_language") or "zh-CN",
            "navigator_languages": list(profile.get("navigator_languages") or []),
            "timezone_iana": profile.get("timezone_iana") or "",
            "timezone_offset_minutes": int(profile.get("timezone_offset_minutes", 0) or 0),
            "timezone_name": profile.get("timezone_name") or "",
            "screen_width": int(profile.get("screen_width", 0) or 0),
            "screen_height": int(profile.get("screen_height", 0) or 0),
            "device_pixel_ratio": profile.get("device_pixel_ratio") or 0,
            "hardware_concurrency": profile.get("hardware_concurrency") or 0,
            "device_memory": profile.get("device_memory") or 0,
            "js_heap_size_limit": profile.get("js_heap_size_limit") or 0,
            "sec_ch_ua": profile.get("sec_ch_ua") or "",
            "sec_ch_ua_platform": profile.get("sec_ch_ua_platform") or "",
            "sec_ch_ua_platform_version": profile.get("sec_ch_ua_platform_version") or "",
            "sec_ch_ua_mobile": profile.get("sec_ch_ua_mobile") or "",
            "sec_ch_ua_arch": profile.get("sec_ch_ua_arch") or "",
            "sec_ch_ua_bitness": profile.get("sec_ch_ua_bitness") or "",
            "sec_ch_ua_model": profile.get("sec_ch_ua_model") or "",
            "sec_ch_ua_full_version_list": profile.get("sec_ch_ua_full_version_list") or "",
            "react_listening_key": profile.get("react_listening_key") or "",
            "react_container_key": profile.get("react_container_key") or "",
            "react_resources_key": profile.get("react_resources_key") or "",
            "sentinel_sid": self.sentinel_sid,
            "oai_session_id": self.oai_session_id,
            "auth_session_logging_id": self.auth_session_logging_id,
            "datadog_trace_id": self.datadog_trace_id,
            "datadog_parent_id": self.datadog_parent_id,
            "geo_country": geo.get("country") or "",
            "geo_city": geo.get("city") or "",
            "geo_timezone": geo.get("timezone") or "",
            "geo_org": geo.get("org") or "",
        }
        return summary

    def fingerprint_summary_text(self) -> str:
        """Compress the summary into one line, convenient for log output."""
        p = self.fingerprint_summary()
        parts = [
            f"device_id={self._short_value(p.get('device_id'), 12)}",
            f"proxy={self._short_value(p.get('proxy') or 'direct', 36)}",
            f"ua={self._short_value(p.get('user_agent'), 72)}",
            f"lang={p.get('accept_language')}",
            f"tz={p.get('timezone_iana')}({p.get('timezone_offset_minutes')})",
            f"screen={p.get('screen_width')}x{p.get('screen_height')}@{p.get('device_pixel_ratio')}",
            f"cpu={p.get('hardware_concurrency')}",
            f"mem={p.get('device_memory')}",
            f"geo={p.get('geo_country') or '?'}:{p.get('geo_city') or '?'}",
        ]
        return " ".join(parts)

    def _observe_cf_cookie_changes(self, url: str) -> None:
        current = self.cf_cookie_snapshot()
        if current != getattr(self, "_cf_cookie_seen", {}):
            logger.info("[CF] Cookie state update url=%s keys=%s", url, sorted(current.keys()))
            self._cf_cookie_seen = current

    def _enforce_proxy_quality(self) -> None:
        """Roughly judge the proxy quality from the GeoIP org/ASN; cloud-vendor/DC exits are rejected by default."""
        try:
            from config import browser as _browser_cfg
            reject = bool(getattr(_browser_cfg, "REJECT_CLOUD_PROXY", True))
            keywords = list(getattr(_browser_cfg, "CLOUD_PROXY_ORG_KEYWORDS", []) or [])
        except Exception:
            return
        if not reject or not self.exit_geo:
            return
        org = str(self.exit_geo.get("org") or "").lower()
        if not org:
            return
        hit = next((kw for kw in keywords if kw and str(kw).lower() in org), "")
        if hit:
            raise RuntimeError(
                f"The proxy exit looks like a cloud vendor/DC, registration refused to continue:"
                f"ip={self.exit_geo.get('ip') or '?'} country={self.exit_geo.get('country') or '?'} "
                f"org={self.exit_geo.get('org') or '?'} hit={hit}. "
                f"If you confirm it is a residential proxy, you can set REJECT_CLOUD_PROXY=False."
            )

    def _cookie_header_for_domain(self, domain: str) -> str:
        """Export the Cookies of the current session visible to the given domain, for the Node VM document.cookie."""
        pairs = []
        wanted = domain.lower().lstrip(".")
        try:
            for cookie in self.session.cookies.jar:
                name = getattr(cookie, "name", "")
                value = getattr(cookie, "value", "")
                cdom = str(getattr(cookie, "domain", "") or "").lower().lstrip(".")
                if not name:
                    continue
                if cdom and not (wanted == cdom or wanted.endswith("." + cdom) or cdom.endswith("." + wanted)):
                    continue
                pairs.append(f"{name}={value}")
        except Exception:
            pass
        return "; ".join(pairs)

    def auth_cookie_header(self) -> str:
        return self._cookie_header_with_device("auth.openai.com")

    def chatgpt_cookie_header(self) -> str:
        return self._cookie_header_with_device("chatgpt.com")

    def _cookie_header_with_device(self, domain: str) -> str:
        """Export the Cookies and make sure the device/language cookies are not lost through the Jar merge."""
        existing = self._cookie_header_for_domain(domain)
        pairs = [p.strip() for p in existing.split(";") if p.strip()]
        names = {p.split("=", 1)[0].strip() for p in pairs if "=" in p}
        if "oai-did" not in names:
            pairs.append(f"oai-did={self.device_id}")
        if "oai-locale" not in names:
            pairs.append(f"oai-locale={self.navigator_language()}")
        return "; ".join(pairs)

    def chatgpt_cookie_header_with_device(self) -> str:
        """Compatible with the explicit API of the link extraction project, for call sites that need a manual Cookie header."""
        return self._cookie_header_with_device("chatgpt.com")

    def _detect_exit_geo(self) -> dict:
        """Detect the exit IP geo information through the current proxy; on failure return an empty dict and fall back to the default region profile."""
        try:
            from config import browser as _browser_cfg
            if not getattr(_browser_cfg, "AUTO_BROWSER_LOCALE_FROM_IP", True):
                return {}
            endpoints = list(getattr(_browser_cfg, "IP_GEO_ENDPOINTS", []) or [])
            timeout = float(getattr(_browser_cfg, "IP_GEO_TIMEOUT", 6) or 6)
        except Exception:
            return {}

        cache_key = self.proxy or "__direct__"
        with _GEO_CACHE_LOCK:
            cached = _GEO_CACHE.get(cache_key)
            if cached is not None:
                return dict(cached)

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        for url in endpoints:
            try:
                resp = self.session.get(url, headers=headers, timeout=timeout)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                geo = self._normalize_geo_response(data)
                if geo.get("country") or geo.get("timezone"):
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[cache_key] = dict(geo)
                    logger.info(
                        "[fingerprint] Exit IP geo information: ip=%s country=%s city=%s timezone=%s",
                        geo.get("ip") or "?", geo.get("country") or "?",
                        geo.get("city") or "?", geo.get("timezone") or "?",
                    )
                    return geo
            except Exception as exc:
                logger.debug(f"[fingerprint] Exit IP geo detection failed endpoint={url}: {type(exc).__name__}: {exc}")
                continue
        with _GEO_CACHE_LOCK:
            _GEO_CACHE[cache_key] = {}
        return {}

    @staticmethod
    def _normalize_country_code(value: object) -> str:
        text = str(value or "").strip().upper().replace("_", " ")
        if len(text) == 2 and text.isalpha():
            return text
        return _COUNTRY_NAME_TO_CODE.get(text, text if len(text) == 2 else "")

    @staticmethod
    def _normalize_geo_response(data: dict) -> dict:
        """Compatible with common JSON fields of ipinfo / ipapi / ipwho.is and similar."""
        if not isinstance(data, dict):
            return {}
        timezone = data.get("timezone")
        if isinstance(timezone, dict):
            timezone = timezone.get("id") or timezone.get("name")
        # ipwho.is country="Japan" and country_code="JP"; the old logic preferred country
        # would get the pseudo code JAPAN, and the language profile then wrongly fell back to en-US. Always prefer the ISO fields.
        raw_country = data.get("country_code") or data.get("countryCode")
        if not raw_country:
            country_obj = data.get("country")
            if isinstance(country_obj, dict):
                raw_country = country_obj.get("code") or country_obj.get("iso_code") or country_obj.get("name")
            else:
                raw_country = country_obj
        return {
            "ip": data.get("ip") or data.get("query"),
            "country": BrowserSession._normalize_country_code(raw_country),
            "region": data.get("region") or data.get("regionName"),
            "city": data.get("city"),
            "timezone": timezone or "",
            "org": data.get("org") or data.get("isp") or data.get("connection", {}).get("org"),
        }

    def _get_common_headers(self) -> dict:
        """Get the generic request headers, preferring the stable profile of this BrowserSession."""
        profile = getattr(self, "browser_profile", {}) or {}
        headers = {
            "User-Agent": str(profile.get("user_agent") or USER_AGENT),
            "accept-language": str(profile.get("accept_language") or ACCEPT_LANGUAGE),
        }

        # Safari Chromium Client Hints are not sent; sec-ch-* is only added for Chrome/Chromium profiles.
        send_client_hints = bool(profile.get("send_client_hints", bool(SEC_CH_UA)))
        if send_client_hints:
            if profile.get("sec_ch_ua") or SEC_CH_UA:
                headers["sec-ch-ua"] = str(profile.get("sec_ch_ua") or SEC_CH_UA)
            if profile.get("sec_ch_ua_mobile") or SEC_CH_UA_MOBILE:
                headers["sec-ch-ua-mobile"] = str(profile.get("sec_ch_ua_mobile") or SEC_CH_UA_MOBILE)
            if profile.get("sec_ch_ua_platform") or SEC_CH_UA_PLATFORM:
                headers["sec-ch-ua-platform"] = str(profile.get("sec_ch_ua_platform") or SEC_CH_UA_PLATFORM)
            if SEND_HIGH_ENTROPY_CLIENT_HINTS:
                headers.update({
                    "sec-ch-ua-full-version-list": str(profile.get("sec_ch_ua_full_version_list") or SEC_CH_UA_FULL_VERSION_LIST),
                    "sec-ch-ua-platform-version": str(profile.get("sec_ch_ua_platform_version") or SEC_CH_UA_PLATFORM_VERSION),
                    "sec-ch-ua-arch": str(profile.get("sec_ch_ua_arch") or SEC_CH_UA_ARCH),
                    "sec-ch-ua-bitness": str(profile.get("sec_ch_ua_bitness") or SEC_CH_UA_BITNESS),
                    "sec-ch-ua-model": str(profile.get("sec_ch_ua_model") or SEC_CH_UA_MODEL),
                })
        return headers

    def navigator_language(self) -> str:
        """The navigator.language in the current session profile."""
        return str((getattr(self, "browser_profile", {}) or {}).get("navigator_language") or "zh-CN")

    @staticmethod
    def _sec_fetch_site_for(target_origin: str, referer: str) -> str:
        """Roughly simulate the Sec-Fetch-Site of a browser according to the Referer."""
        ref = (referer or "").lower()
        target = target_origin.lower().rstrip("/")
        if ref.startswith(target):
            return "same-origin"
        if ref.startswith("https://chatgpt.com") or ref.startswith("https://auth.openai.com") or ref.startswith("https://sentinel.openai.com"):
            return "cross-site"
        return "none"

    def get_datadog_headers(self) -> dict:
        """Get the stable Datadog/RUM correlation headers of the current session."""
        return {
            "x-datadog-origin": self.datadog_origin,
            "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": self.datadog_trace_id,
            "x-datadog-parent-id": self.datadog_parent_id,
        }

    def get_trace_context_headers(self) -> dict:
        """Fill in the W3C traceparent / Datadog tracestate seen in the Auth Web capture."""
        trace_hex = format(int(self.datadog_trace_id), "032x")[-32:]
        parent_hex = format(int(self.datadog_parent_id), "016x")[-16:]
        return {
            "traceparent": f"00-{trace_hex}-{parent_hex}-01",
            "tracestate": f"dd=s:1;o:{self.datadog_origin}",
        }

    def _attach_auth_rum_headers(self, headers: dict) -> dict:
        """Auth Web JSON API headers: only RUM/trace/access-flow appear in the HAR, without oai-client-*."""
        # A browser creates a new span for every fetch, instead of reusing the same trace for the whole login chain.
        self.datadog_trace_id = str(random.getrandbits(64) or 1)
        self.datadog_parent_id = str(random.getrandbits(64) or 1)
        headers.update(self.get_trace_context_headers())
        headers["x-access-flow-invocation-id"] = str(uuid.uuid4())
        headers["x-openai-document-navigation-id"] = self.document_navigation_id
        headers.update(self.get_datadog_headers())
        return headers

    def rotate_document_navigation_id(self) -> str:
        self.document_navigation_id = str(uuid.uuid4())
        return self.document_navigation_id

    def js_timezone_offset_min(self) -> int:
        """Returns the semantics of JS Date.getTimezoneOffset(): UTC-local, -480 for UTC+8."""
        profile = getattr(self, "browser_profile", {}) or {}
        return -int(profile.get("timezone_offset_minutes", 0) or 0)

    def _attach_datadog_headers(self, headers: dict) -> dict:
        """Fill in the Datadog headers for front-end API requests, lowering the probability of a silent drop for requests without diagnostic headers."""
        headers.update(self.get_datadog_headers())
        return headers

    def _attach_oai_context_headers(self, headers: dict) -> dict:
        """Fill in the same device context headers, consistent with the oai-did Cookie / OAuth ext-oai-did."""
        headers["oai-client-build-number"] = str(getattr(self, "client_build_number", OAI_CLIENT_BUILD_NUMBER))
        headers["oai-client-version"] = str(getattr(self, "client_version", OAI_CLIENT_VERSION))
        headers["oai-device-id"] = self.device_id
        headers["oai-language"] = self.navigator_language()
        headers["oai-session-id"] = self.oai_session_id
        return headers

    def observe_chatgpt_document(self, response) -> None:
        """Sync the ChatGPT front-end build metadata from the real login page HTML of this run."""
        try:
            final_url = str(getattr(response, "url", "") or "")
            if urlparse(final_url).hostname != "chatgpt.com":
                return
            html = str(getattr(response, "text", "") or "")
            build = re.search(r'\bdata-build=["\']([^"\']+)', html[:200000])
            seq = re.search(r'\bdata-seq=["\']([^"\']+)', html[:200000])
            if build:
                self.client_version = build.group(1)
                self.browser_profile["build_id"] = self.client_version
            if seq:
                self.client_build_number = seq.group(1)
            if build or seq:
                logger.info(
                    "[fingerprint] Synced the front-end version from the ChatGPT login page:build=%s seq=%s",
                    self.client_version, self.client_build_number,
                )
        except Exception as exc:
            logger.debug("[fingerprint] Failed to parse the build of the ChatGPT login page:%s", exc)

    def _attach_frontend_api_headers(self, headers: dict) -> dict:
        """Unified headers of the front-end APIs: BrowserProfile + oai context + Datadog."""
        self._attach_oai_context_headers(headers)
        self._attach_datadog_headers(headers)
        return headers

    def get_nextauth_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """NextAuth `/api/auth/*` headers; the HAR does not carry oai-client-*."""
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
        })
        return headers

    def get_chatgpt_headers(self, referer: str = "https://chatgpt.com/login") -> dict:
        """
        Get the request headers of the chatgpt.com domain.
        Used for steps 1-3.
        """
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
        })
        return self._attach_frontend_api_headers(headers)

    def get_auth_headers(self, referer: str = "https://auth.openai.com/create-account/password") -> dict:
        """
        Get the request headers of the auth.openai.com domain.
        Used for steps 7, 10, 12.
        """
        headers = self._get_common_headers()
        headers.update({
            "accept": "application/json",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
            "origin": "https://auth.openai.com",
        })
        return self._attach_auth_rum_headers(headers)

    def get_auth_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True, target_origin: str = "https://auth.openai.com") -> dict:
        """
        Get the navigation request headers of auth.openai.com (for GET page requests).
        Used for steps 4, 5, 8.
        """
        headers = self._get_common_headers()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": self._sec_fetch_site_for(target_origin, referer),
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "priority": "u=0, i",
            "upgrade-insecure-requests": "1",
        })
        if referer:
            headers["referer"] = referer
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        # document Navigation is issued by the browser network stack and does not carry the
        # x-datadog-* custom headers used by fetch/XHR; a cross-site OAuth navigation in particular needs to keep the native header set.
        return headers

    def get_chatgpt_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True) -> dict:
        """Get the page navigation request headers of chatgpt.com, for warming up the login page / returning to the app page."""
        headers = self._get_common_headers()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": self._sec_fetch_site_for("https://chatgpt.com", referer),
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "priority": "u=0, i",
            "upgrade-insecure-requests": "1",
        })
        if referer:
            headers["referer"] = referer
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        return headers

    def get_sentinel_headers(self) -> dict:
        """
        Get the request headers of sentinel.openai.com.
        Used for steps 6, 9, 11.
        """
        from config import SENTINEL_SV
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://sentinel.openai.com",
            "referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SV}",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "priority": "u=1, i",
        })
        # The Sentinel iframe fetch of a successful browser sample carries no oai-client-* or
        # x-datadog-*, keeping only the standard CORS request headers.
        return headers

    def get_sentinel_frame_headers(self, user_initiated: bool = False) -> dict:
        """Sentinel SDK iframe same-site document navigation headers."""
        headers = self._get_common_headers()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "referer": "https://auth.openai.com/",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "iframe",
            "priority": "u=0, i",
            "upgrade-insecure-requests": "1",
        })
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        return headers


    @staticmethod
    def _chatgpt_target_route(path: str) -> str:
        """Normalize the real URL path into the x-openai-target-route shape seen in the HAR."""
        if path.startswith("/backend-api/accounts/check/"):
            return "/backend-api/accounts/check/{version}"
        if path.startswith("/backend-anon/accounts/check/"):
            return "/backend-anon/accounts/check/{version}"
        if path.startswith("/backend-api/conversation/") and path != "/backend-api/conversation/init":
            return "/backend-api/conversation/{conversation_id}"
        if path.startswith("/backend-anon/conversation/") and path != "/backend-anon/conversation/init":
            return "/backend-anon/conversation/{conversation_id}"
        return path

    def _attach_openai_target_headers_for_url(self, url: str, headers: dict | None) -> dict | None:
        """
        Automatically fill in the target diagnostic headers of the chatgpt.com front-end APIs seen in the HAR.

        NextAuth `/api/auth/*` and the auth.openai.com JSON APIs carry no such headers in the capture;
        here they are only filled in for the backend/ces front-end endpoints of chatgpt.com, so call sites need not maintain them by hand.
        """
        if headers is None:
            return headers
        try:
            parsed = urlparse(str(url))
        except Exception:
            return headers
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        if host != "chatgpt.com":
            return headers
        if not (path.startswith("/backend-api/") or path.startswith("/backend-anon/") or path.startswith("/ces/")):
            return headers
        # Values explicitly specified by the caller are not overridden, which makes it easy to adjust special endpoints individually later.
        headers.setdefault("x-openai-target-path", path)
        headers.setdefault("x-openai-target-route", self._chatgpt_target_route(path))
        return headers

    def _raise_if_circuit_open(self) -> None:
        if self.blocked_until and time.time() < self.blocked_until:
            remain = max(0, int(self.blocked_until - time.time()))
            raise RuntimeError(f"The current BrowserSession is in circuit breaker cooldown ({remain}s remaining):{self.blocked_reason}")

    def reset_circuit_breaker(self) -> None:
        """Clear the local circuit breaker state produced by one optional warm-up.

        When some best-effort bootstrap endpoint returns a 403, it does not mean the following real authentication endpoints
        are unavailable; after isolating the error, the caller can explicitly resume this session to continue.
        """
        self.blocked_until = 0.0
        self.blocked_reason = ""

    @staticmethod
    def _parse_retry_after(value: str | None) -> int:
        if not value:
            return 0
        text = str(value).strip()
        if text.isdigit():
            return max(0, int(text))
        return 0

    def _observe_response_for_circuit_breaker(self, resp, url: str):
        status = int(getattr(resp, "status_code", 0) or 0)
        self._observe_cf_cookie_changes(url)
        if status not in (403, 429):
            return resp
        retry_after = self._parse_retry_after(getattr(resp, "headers", {}).get("retry-after") if getattr(resp, "headers", None) else None)
        cool_down = retry_after if retry_after > 0 else (300 if status == 429 else 900)
        self.blocked_until = max(self.blocked_until, time.time() + min(cool_down, 3600))
        self.blocked_reason = f"HTTP {status} from {url}"
        logger.warning("[circuit breaker] The current session received HTTP %s, entering a cooldown of %ss and stopping later requests:%s", status, min(cool_down, 3600), url)
        return resp

    def get(self, url: str, headers: dict = None, **kwargs):
        """Send a GET request"""
        self._raise_if_circuit_open()
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.get(url, headers=headers, **kwargs)
        return self._observe_response_for_circuit_breaker(resp, url)

    def post(self, url: str, headers: dict = None, **kwargs):
        """Send a POST request"""
        self._raise_if_circuit_open()
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.post(url, headers=headers, **kwargs)
        return self._observe_response_for_circuit_breaker(resp, url)
