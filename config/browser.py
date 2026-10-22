# -*- coding: utf-8 -*-
"""
Browser fingerprint and HTTP client configuration.

One single browser environment profile is maintained here and used by three layers at the same time:
1. curl_cffi TLS / HTTP headers;
2. Python side generates the initial Sentinel p;
3. Node VM side runs sdk.js.

Principle: stable within one BrowserSession, naturally spread across different BrowserSessions; protocol headers,JS
navigator/screen/timezone/client hints must not contradict each other.
"""
from __future__ import annotations

from config.env_loader import apply_env_overrides

import random
import re
from datetime import datetime
from zoneinfo import ZoneInfo


def _latest_chrome_major(default: str = "146") -> str:
    """Kept for legacy module imports; must match the TLS impersonate version curl_cffi actually uses."""
    return default


CHROME_MAJOR = "146"
CHROME_FULL_VERSION = "146.0.0.0"

SAFARI_VERSION = ""
SAFARI_WEBKIT_VERSION = "537.36"
MAC_OS_UA_VERSION = "10_15_7"

# ---------- curl_cffi impersonated browser ----------
# curl_cffi 0.15 The highest built-in version is currently chrome146. UA, Client Hints,JS navigator
# must be synchronized to 146; a cross-version fingerprint such as TLS=146 with HTTP/JS=149 must never appear.
IMPERSONATE = "chrome146"

# ---------- Desktop Chrome profile ----------
BROWSER_FAMILY = "chrome"
BROWSER_OS = "macOS"
# OS The related fields must agree across UA / Client Hints / JS navigator.
NAVIGATOR_PLATFORM = "MacIntel"
NAVIGATOR_VENDOR = "Google Inc."
USER_AGENT_DATA_PLATFORM = "macOS"
USER_AGENT = (
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X {MAC_OS_UA_VERSION}) "
    f"AppleWebKit/{SAFARI_WEBKIT_VERSION} (KHTML, like Gecko) "
    f"Chrome/{CHROME_FULL_VERSION} Safari/{SAFARI_WEBKIT_VERSION}"
)

# Must exactly match the brand order and GREASE brand that curl_cffi chrome146 really sends.
# The old value used the Google Chrome/Chromium/Not)A;Brand order of Chrome149 from the HAR,
# but the TLS impersonate had already switched to chrome146, which made the network stack conflict with the explicit Client Hints.
SEC_CH_UA = '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"'
SEC_CH_UA_FULL_VERSION_LIST = '"Chromium";v="146.0.0.0", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.0.0"'
SEC_CH_UA_PLATFORM = '"macOS"'
SEC_CH_UA_PLATFORM_VERSION = '"15.7.0"'
SEC_CH_UA_MOBILE = "?0"
SEC_CH_UA_ARCH = '"arm"'
SEC_CH_UA_BITNESS = '"64"'
SEC_CH_UA_MODEL = '""'
SEND_CLIENT_HINTS = True
SEND_HIGH_ENTROPY_CLIENT_HINTS = False

# ---------- Language / timezone ----------
BROWSER_LOCALE_PROFILE = "jp"
AUTO_BROWSER_LOCALE_FROM_IP = True
IP_GEO_TIMEOUT = 6.0
IP_GEO_ENDPOINTS = [
    "https://ipinfo.io/json",
    "https://ipapi.co/json",
    "https://ipwho.is/",
]

# Proxy exit quality diagnostics: not blocked by default, only rejects cloud-vendor/DC ASNs when manually enabled.
# Users may deliberately use a fixed cloud exit to reproduce captures, so the default is False.
REJECT_CLOUD_PROXY = False
CLOUD_PROXY_ORG_KEYWORDS = [
    "amazon", "aws", "google cloud", "google llc", "microsoft", "azure",
    "digitalocean", "linode", "akamai", "ovh", "hetzner", "oracle",
    "tencent", "alibaba", "aliyun", "huawei cloud", "vultr", "contabo",
    "data center", "datacenter", "hosting", "host", "server", "cloud",
]

# ---------- Roxy/Cloak browser traffic-saving mode ----------
# Off by default. When enabled it blocks optional images/media and explicitly listed analytics URLs,
# and blocks the download domains below in the local browser proxy relay layer;
# it does not block the document, core script, stylesheet, xhr/fetch and websocket needed for login;
# Playwright URLs containing captcha/challenge keywords are allowed through.
# This mode only applies to Roxy/Cloak, where a local browser needs to save bandwidth; Browser Use/Skyvern cloud
# browsers do not install the traffic-saving interceptor. Selenium/CDP can only block by URL suffix; turn it off if captchas misbehave.
BROWSER_DATA_SAVER_MODE: bool = False
# Blocked by target host before the proxy connects, including subdomains, covering startup and background component downloads.
# Only effective when a local browser uses the metered relay and traffic-saving mode is on; [] disables domain blocking.
BROWSER_DATA_SAVER_BLOCKED_PROXY_HOSTS: list[str] = ["dl.google.com", "gvt1.com"]
# After registration has obtained the accessToken, block ChatGPT app-shell/telemetry resources that are no longer needed.
# Only effective in the post-registration phase of Roxy/Cloak; does not affect email, verification codes or the login page.
BROWSER_DATA_SAVER_DEEP_MODE: bool = True
# One Playwright resource_type per line. Options include image/media/font/manifest/texttrack etc.;
# by default only image and media are blocked; resources such as stylesheet/font can also be configured; Roxy additionally disables image loading via Chromium launch arguments,
# turn the mode off if the page layout or captcha misbehaves.
BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES: list[str] = ["image", "media"]
# URL glob extra blocking at the level of. The following are ad/analytics resources confirmed from the resource breakdown not to take part in the email-and-password registration main flow
# RUM/ad analytics resources; Google GSI is only used for Google sign-in and is blocked by default when Google sign-in is not used.
# Do not treat CDN chunks of ChatGPT/auth.openai as candidates: even if only a few functions of a chunk are called,
# it may be responsible for routing, form switching or lazy loading; it can only be added to the rules after a single-variable A/B verification.
# Do not add core chatgpt/openai APIs or sentinel URLs here.
# `**` Used to match any path in a URL; the Playwright/Selenium of Roxy/Cloak reads this rule set.
BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS: list[str] = [
    "**://auth.openai.com/awe/api/v2/rum**",
    "**://chatgpt.com/awe/api/v2/rum**",
    "**://chatgpt.com/ces/statsc/flush**",
    "**://connect.facebook.net/**",
    "**://analytics.tiktok.com/**",
    "**://snap.licdn.com/**",
    "**://bat.bing.com/**",
    "**://accounts.google.com/gsi/client**",
]

# ---------- Roxy/Cloak browser traffic detail log ----------
# Off by default; when enabled, only requests that consumed traffic are printed at the end of registration, with upload/download/total bytes.
# Sorted by total per-request consumption in descending order; blocked, zero-byte and local requests are skipped, and estimated items are explicitly marked.
# URL Query parameter values are masked; request/response bodies and full header contents are not saved.
BROWSER_TRAFFIC_DETAIL_LOG: bool = False
BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES: int = 2000

# ---------- Roxy/Cloak browser JS precise coverage ----------
# When enabled, the Chrome DevTools Protocol Profiler records the
# JavaScript functions/code ranges actually executed in this session. Only function names, call counts and offsets are saved; arguments, return values
# or source code are not read; Browser Use/Skyvern cloud browsers do not enable this listener; off by default to avoid extra overhead for normal registration.
BROWSER_JS_COVERAGE_LOG: bool = False
BROWSER_JS_COVERAGE_MAX_ENTRIES: int = 1000
COUNTRY_LOCALE_PROFILE_MAP = {
    "JP": "jp", "CN": "cn", "HK": "hk", "TW": "tw", "US": "us", "CA": "us",
    "SG": "sg", "GB": "gb", "AU": "gb", "DE": "de", "FR": "fr", "NL": "nl",
    "VN": "vn",
}

# For exit countries without a dedicated full profile, at least the browser language is matched automatically. The timezone still uses IP
# the value returned by the geo API directly; this way switching the proxy country does not fall back to a fixed ja-JP/Asia-Tokyo.
COUNTRY_LANGUAGE_TAG_MAP = {
    "TH": "th-TH", "ID": "id-ID", "MY": "ms-MY", "PH": "en-PH",
    "KR": "ko-KR", "IN": "en-IN", "BR": "pt-BR", "MX": "es-MX",
    "ES": "es-ES", "IT": "it-IT", "PT": "pt-PT", "PL": "pl-PL",
    "RU": "ru-RU", "TR": "tr-TR", "AE": "ar-AE", "SA": "ar-SA",
    "ZA": "en-ZA", "NZ": "en-NZ", "IE": "en-IE", "AT": "de-AT",
    "CH": "de-CH", "BE": "nl-BE", "SE": "sv-SE", "NO": "nb-NO",
    "DK": "da-DK", "FI": "fi-FI", "CZ": "cs-CZ", "RO": "ro-RO",
    "HU": "hu-HU", "GR": "el-GR", "IL": "he-IL", "UA": "uk-UA",
}

BROWSER_LOCALE_PROFILES = {
    "jp": {"navigator_language": "ja-JP", "navigator_languages": ["ja-JP"], "accept_language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Tokyo", "timezone_offset_minutes": 9 * 60, "timezone_name": "Japan Standard Time"},
    "cn": {"navigator_language": "zh-CN", "navigator_languages": ["zh-CN"], "accept_language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Shanghai", "timezone_offset_minutes": 8 * 60, "timezone_name": "China Standard Time"},
    "us": {"navigator_language": "en-US", "navigator_languages": ["en-US"], "accept_language": "en-US,en;q=0.9", "timezone_iana": "America/Los_Angeles", "timezone_offset_minutes": -7 * 60, "timezone_name": "Pacific Daylight Time"},
    "sg": {"navigator_language": "en-SG", "navigator_languages": ["en-SG"], "accept_language": "en-SG,en-US;q=0.9,en;q=0.8", "timezone_iana": "Asia/Singapore", "timezone_offset_minutes": 8 * 60, "timezone_name": "Singapore Standard Time"},
    "hk": {"navigator_language": "zh-HK", "navigator_languages": ["zh-HK"], "accept_language": "zh-HK,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6", "timezone_iana": "Asia/Hong_Kong", "timezone_offset_minutes": 8 * 60, "timezone_name": "Hong Kong Standard Time"},
    "tw": {"navigator_language": "zh-TW", "navigator_languages": ["zh-TW"], "accept_language": "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Taipei", "timezone_offset_minutes": 8 * 60, "timezone_name": "Taipei Standard Time"},
    "gb": {"navigator_language": "en-GB", "navigator_languages": ["en-GB"], "accept_language": "en-GB,en-US;q=0.9,en;q=0.8", "timezone_iana": "Europe/London", "timezone_offset_minutes": 1 * 60, "timezone_name": "British Summer Time"},
    "de": {"navigator_language": "de-DE", "navigator_languages": ["de-DE"], "accept_language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Berlin", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "fr": {"navigator_language": "fr-FR", "navigator_languages": ["fr-FR"], "accept_language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Paris", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "nl": {"navigator_language": "nl-NL", "navigator_languages": ["nl-NL"], "accept_language": "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Amsterdam", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "vn": {"navigator_language": "vi-VN", "navigator_languages": ["vi-VN", "vi", "en-US", "en"], "accept_language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Ho_Chi_Minh", "timezone_offset_minutes": 7 * 60, "timezone_name": "Indochina Time"},
}

TIMEZONE_NAME_BY_IANA = {
    "Asia/Tokyo": "Japan Standard Time",
    "Asia/Shanghai": "China Standard Time",
    "Asia/Singapore": "Singapore Standard Time",
    "Asia/Hong_Kong": "Hong Kong Standard Time",
    "Asia/Taipei": "Taipei Standard Time",
    "America/Los_Angeles": "Pacific Daylight Time",
    "America/New_York": "Eastern Daylight Time",
    "America/Chicago": "Central Daylight Time",
    "America/Denver": "Mountain Daylight Time",
    "Europe/London": "British Summer Time",
    "Europe/Berlin": "Central European Summer Time",
    "Europe/Paris": "Central European Summer Time",
    "Europe/Amsterdam": "Central European Summer Time",
    "Asia/Ho_Chi_Minh": "Indochina Time",
    "Asia/Bangkok": "Indochina Time",
}


def _offset_minutes_for_timezone(tz_name: str, default: int) -> int:
    try:
        offset = datetime.now(ZoneInfo(tz_name)).utcoffset()
        if offset is not None:
            return int(offset.total_seconds() // 60)
    except Exception:
        pass
    return int(default)


def _locale_profile_key_from_geo(geo: dict | None) -> str:
    if not geo or not AUTO_BROWSER_LOCALE_FROM_IP:
        return BROWSER_LOCALE_PROFILE
    country = str(geo.get("country") or geo.get("country_code") or "").upper()
    return COUNTRY_LOCALE_PROFILE_MAP.get(country, BROWSER_LOCALE_PROFILE)


def _build_locale_from_geo(geo: dict | None) -> dict:
    key = _locale_profile_key_from_geo(geo)
    resolved_profile = key
    locale = dict(BROWSER_LOCALE_PROFILES.get(key, BROWSER_LOCALE_PROFILES[BROWSER_LOCALE_PROFILE]))
    if geo and AUTO_BROWSER_LOCALE_FROM_IP:
        country = str(geo.get("country") or geo.get("country_code") or "").upper()
        # Dedicated profiles cover common countries; language fields are generated dynamically for other known countries. If the geo API
        # returns an unknown country, the neutral en-US is used instead of leaking the local default Japanese profile.
        if country not in COUNTRY_LOCALE_PROFILE_MAP:
            language_tag = COUNTRY_LANGUAGE_TAG_MAP.get(country, "en-US")
            resolved_profile = f"geo:{country.lower() or 'unknown'}"
            base_language = language_tag.split("-", 1)[0]
            languages = [language_tag]
            if base_language != language_tag:
                languages.append(base_language)
            if base_language != "en":
                languages.extend(["en-US", "en"])
                accept_language = f"{language_tag},{base_language};q=0.9,en-US;q=0.8,en;q=0.7"
            else:
                languages.append("en")
                accept_language = f"{language_tag},en;q=0.9"
            locale.update({
                "navigator_language": language_tag,
                "navigator_languages": list(dict.fromkeys(languages)),
                "accept_language": accept_language,
            })
        tz = str(geo.get("timezone") or "").strip()
        if tz:
            locale["timezone_iana"] = tz
            locale["timezone_offset_minutes"] = _offset_minutes_for_timezone(tz, int(locale["timezone_offset_minutes"]))
            locale["timezone_name"] = TIMEZONE_NAME_BY_IANA.get(tz, locale.get("timezone_name", ""))
    locale["locale_profile"] = resolved_profile
    return locale


_LOCALE = BROWSER_LOCALE_PROFILES.get(BROWSER_LOCALE_PROFILE, BROWSER_LOCALE_PROFILES["jp"])
NAVIGATOR_LANGUAGE = _LOCALE["navigator_language"]
NAVIGATOR_LANGUAGES = list(_LOCALE["navigator_languages"])
ACCEPT_LANGUAGE = _LOCALE["accept_language"]
TIMEZONE_IANA = _LOCALE["timezone_iana"]
TIMEZONE_OFFSET_MINUTES = int(_LOCALE["timezone_offset_minutes"])
TIMEZONE_NAME = _LOCALE["timezone_name"]

# ---------- Sentinel / JS VM environment ----------
SCREEN_WIDTH = 1680
SCREEN_HEIGHT = 1050
HARDWARE_CONCURRENCY = 6
JS_HEAP_SIZE_LIMIT = 4395630592
DEVICE_MEMORY = 8

# These lists must stay consistent with createBrowserContext in sentinel/sentinel-runner.js.
NAVIGATOR_PROTO_SAMPLES = [
    "createAuctionNonce−function createAuctionNonce() { [native code] }",
    "clearOriginJoinedAdInterestGroups−function clearOriginJoinedAdInterestGroups() { [native code] }",
    "updateAdInterestGroups−function updateAdInterestGroups() { [native code] }",
    "canLoadAdAuctionFencedFrame−function canLoadAdAuctionFencedFrame() { [native code] }",
    "gpu−[object GPU]",
    "getBattery−function getBattery() { [native code] }",
    "getGamepads−function getGamepads() { [native code] }",
    "javaEnabled−function javaEnabled() { [native code] }",
    "sendBeacon−function sendBeacon() { [native code] }",
    "vibrate−function vibrate() { [native code] }",
    "login−[object NavigatorLogin]",
]
DOCUMENT_KEY_SAMPLES = [
    "currentScript", "scripts", "cookie", "URL", "documentURI", "referrer",
    "title", "characterSet", "charset", "compatMode", "contentType", "readyState",
    "visibilityState", "hidden", "hasFocus", "documentElement", "body",
    "addEventListener", "removeEventListener", "querySelector", "querySelectorAll",
    "getElementById", "getElementsByTagName", "createElement",
]
WINDOW_KEY_SAMPLES = [
    "window", "self", "top", "parent", "frames", "navigator", "screen", "location",
    "localStorage", "sessionStorage", "history", "innerWidth", "innerHeight",
    "outerWidth", "outerHeight", "devicePixelRatio", "chrome", "performance", "crypto",
    "TextEncoder", "URL", "URLSearchParams", "AbortController",
    "locationbar", "scrollX", "scrollY", "ondevicemotion",
    "requestAnimationFrame", "queueMicrotask", "onfocus", "onblur", "onpageshow",
]

SCRIPT_SRC_SAMPLES = [
    "https://accounts.google.com/gsi/client",
    "https://chatgpt.com/cdn-cgi/challenge-platform/scripts/jsd/api.js?onload=jsdOnload",
    "https://sentinel.openai.com/sentinel/20260810913b/sdk.js",
]

WINDOW_FEATURE_FLAGS = {
    "ai": 0,
    "InstallTrigger": 0,
    "cache": 0,
    "data": 0,
    "solana": 0,
    "dump": 0,
    # HAR In the sample p[24] is 0; not exposed by default, enabled via the profile switch when necessary.
    "requestIdleCallback": 0,
}

# ---------- HTTP timeout ----------
REQUEST_TIMEOUT = 30

# HAR Reference profile: derived by decoding p[0]/p[2]/p[16] of Default-all-domains-1784468371563.json.
HAR_CAPTURE_BASE_PROFILE = {"screen_width": 1680, "screen_height": 1050, "hardware_concurrency": 6, "device_memory": 8, "js_heap_size_limit": 4395630592, "device_pixel_ratio": 2}

# Pool of common macOS Chrome desktop profiles. Constant within one session; randomly spread across sessions.
# HAR_CAPTURE_BASE_PROFILE is only one of the candidates, not fixed globally.
BROWSER_PROFILE_POOL = [
    HAR_CAPTURE_BASE_PROFILE,
    {"screen_width": 1440, "screen_height": 900,  "hardware_concurrency": 8,  "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 1512, "screen_height": 982,  "hardware_concurrency": 8,  "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 1680, "screen_height": 1050, "hardware_concurrency": 8,  "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 1728, "screen_height": 1117, "hardware_concurrency": 10, "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 1800, "screen_height": 1169, "hardware_concurrency": 10, "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
    {"screen_width": 2056, "screen_height": 1329, "hardware_concurrency": 12, "device_memory": 8, "js_heap_size_limit": 4294967296, "device_pixel_ratio": 2},
]


def build_browser_environment(geo: dict | None = None, base_profile: dict | None = None) -> dict:
    """Build the full browser environment profile as the single source of truth for all fingerprint fields."""
    locale = _build_locale_from_geo(geo)
    profile = dict(base_profile or random.choice(BROWSER_PROFILE_POOL))
    profile.update({
        "locale_profile": locale.get("locale_profile", BROWSER_LOCALE_PROFILE),
        "geo": dict(geo or {}),
        "timezone_iana": locale["timezone_iana"],
        "timezone_offset_minutes": int(locale["timezone_offset_minutes"]),
        "timezone_name": locale["timezone_name"],
        "navigator_language": locale["navigator_language"],
        "navigator_languages": list(locale["navigator_languages"]),
        "accept_language": locale["accept_language"],
        "browser_family": BROWSER_FAMILY,
        "browser_os": BROWSER_OS,
        "navigator_platform": NAVIGATOR_PLATFORM,
        "navigator_vendor": NAVIGATOR_VENDOR,
        "user_agent_data_platform": USER_AGENT_DATA_PLATFORM,
        "safari_version": SAFARI_VERSION,
        "safari_webkit_version": SAFARI_WEBKIT_VERSION,
        "chrome_major": CHROME_MAJOR,
        "chrome_full_version": CHROME_FULL_VERSION,
        "user_agent": USER_AGENT,
        "send_client_hints": SEND_CLIENT_HINTS,
        "sec_ch_ua": SEC_CH_UA,
        "sec_ch_ua_platform": SEC_CH_UA_PLATFORM,
        "sec_ch_ua_platform_version": SEC_CH_UA_PLATFORM_VERSION,
        "sec_ch_ua_arch": SEC_CH_UA_ARCH,
        "sec_ch_ua_bitness": SEC_CH_UA_BITNESS,
        "sec_ch_ua_model": SEC_CH_UA_MODEL,
        "sec_ch_ua_full_version_list": SEC_CH_UA_FULL_VERSION_LIST,
        "sec_ch_ua_mobile": SEC_CH_UA_MOBILE,
        "navigator_proto_samples": list(NAVIGATOR_PROTO_SAMPLES),
        "document_key_samples": list(DOCUMENT_KEY_SAMPLES),
        "window_key_samples": list(WINDOW_KEY_SAMPLES),
        "script_src_samples": list(SCRIPT_SRC_SAMPLES),
        "window_feature_flags": dict(WINDOW_FEATURE_FLAGS),
        "build_id": __import__("config.openai_protocol", fromlist=["OPENAI_BUILD_ID"]).OPENAI_BUILD_ID,
    })
    # Sentinel VM Must use the same screen/window/viewport/GPU profile as the HTTP fingerprint.
    screen_width = int(profile.get("screen_width", 1680))
    screen_height = int(profile.get("screen_height", 1050))
    profile.setdefault("screen_avail_width", screen_width)
    profile.setdefault("screen_avail_height", max(0, screen_height - 25))
    profile.setdefault("color_depth", 24)
    profile.setdefault("outer_width", int(profile["screen_avail_width"]))
    profile.setdefault("outer_height", int(profile["screen_avail_height"]))
    profile.setdefault("viewport_width", int(profile["outer_width"]))
    profile.setdefault("viewport_height", max(0, int(profile["outer_height"]) - 87))
    cores = int(profile.get("hardware_concurrency", 8))
    chip = "Apple M2 Max" if cores >= 12 else "Apple M2 Pro" if cores >= 10 else "Apple M2"
    profile.setdefault("webgl_vendor", "Google Inc. (Apple)")
    profile.setdefault(
        "webgl_renderer",
        f"ANGLE (Apple, ANGLE Metal Renderer: {chip}, Unspecified Version)",
    )
    return profile


def pick_browser_profile(geo: dict | None = None) -> dict:
    """Randomly pick a stable desktop profile for one BrowserSession; the HAR size is only one of the candidates."""
    return build_browser_environment(geo)


def validate_browser_profile(profile: dict) -> list[str]:
    """Return the contradictions inside the profile, mainly for logs/self-tests."""
    issues: list[str] = []
    ua = str(profile.get("user_agent") or "")
    family = str(profile.get("browser_family") or BROWSER_FAMILY)
    if family == "safari":
        if "Version/" not in ua or "Safari/" not in ua or "Chrome/" in ua or "Chromium/" in ua:
            issues.append("Safari UA mismatch")
        if profile.get("send_client_hints"):
            issues.append("Safari must not be sent Chromium Client Hints")
    elif f"Chrome/{profile.get('chrome_full_version')}" not in ua:
        issues.append("UA does not match chrome_full_version")
    if profile.get("browser_os") == "macOS":
        if "Macintosh; Intel Mac OS X" not in ua:
            issues.append("macOS profile but the UA is not Macintosh")
        if str(profile.get("navigator_platform") or "") != "MacIntel":
            issues.append("macOS profile but navigator.platform is not MacIntel")
        if "macOS" not in str(profile.get("sec_ch_ua_platform") or ""):
            issues.append("macOS profile but sec-ch-ua-platform is not macOS")
    if not profile.get("navigator_language"):
        issues.append("navigator_language is empty")
    languages = profile.get("navigator_languages") or []
    if profile.get("navigator_language") and profile.get("navigator_language") not in languages:
        issues.append("navigator.language is not in navigator.languages")
    # requestIdleCallback whether it is exposed is decided by the profile.
    return issues

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'BROWSER_LOCALE_PROFILE': 'str', 'AUTO_BROWSER_LOCALE_FROM_IP': 'bool', 'IP_GEO_TIMEOUT': 'float', 'REJECT_CLOUD_PROXY': 'bool', 'BROWSER_DATA_SAVER_MODE': 'bool', 'BROWSER_DATA_SAVER_BLOCKED_PROXY_HOSTS': 'list_str_multiline', 'BROWSER_DATA_SAVER_DEEP_MODE': 'bool', 'BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES': 'list_str_multiline', 'BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS': 'list_str_multiline', 'BROWSER_TRAFFIC_DETAIL_LOG': 'bool', 'BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES': 'int', 'BROWSER_JS_COVERAGE_LOG': 'bool', 'BROWSER_JS_COVERAGE_MAX_ENTRIES': 'int'})
