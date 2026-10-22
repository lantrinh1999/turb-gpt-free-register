from config.env_loader import load_env
load_env(override=False)

# -*- coding: utf-8 -*-
"""
config package entry point.

To keep the legacy `from config import USER_AGENT` usage working, this file re-exports the constants of all submodules
to the package top level. New code should import from the submodules directly:
    from config.email import EMAIL_SOURCE
    from config.proxy import pick_proxy

Submodules:
    config.browser           browser fingerprint / curl_cffi impersonate / HTTP timeouts
    config.openai_protocol   OpenAI OAuth fixed parameters / Sentinel version
    config.proxy             proxy pool + random pick
    config.register          registration defaults (email, password, name, birthday)
    config.email             Outlook email account pool + OTP polling
    config.twofa             2FA switch
"""

# ---------- Browser / HTTP ----------
from config.browser import (
    USER_AGENT,
    CHROME_MAJOR,
    CHROME_FULL_VERSION,
    BROWSER_OS,
    NAVIGATOR_PLATFORM,
    NAVIGATOR_VENDOR,
    USER_AGENT_DATA_PLATFORM,
    SEC_CH_UA,
    SEC_CH_UA_PLATFORM,
    SEC_CH_UA_MOBILE,
    SEC_CH_UA_FULL_VERSION_LIST,
    SEC_CH_UA_PLATFORM_VERSION,
    SEC_CH_UA_ARCH,
    SEC_CH_UA_BITNESS,
    SEC_CH_UA_MODEL,
    SEND_HIGH_ENTROPY_CLIENT_HINTS,
    ACCEPT_LANGUAGE,
    BROWSER_LOCALE_PROFILE,
    BROWSER_LOCALE_PROFILES,
    AUTO_BROWSER_LOCALE_FROM_IP,
    IP_GEO_TIMEOUT,
    IP_GEO_ENDPOINTS,
    REJECT_CLOUD_PROXY,
    CLOUD_PROXY_ORG_KEYWORDS,
    BROWSER_DATA_SAVER_MODE,
    BROWSER_DATA_SAVER_DEEP_MODE,
    BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES,
    BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS,
    BROWSER_TRAFFIC_DETAIL_LOG,
    BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES,
    BROWSER_JS_COVERAGE_LOG,
    BROWSER_JS_COVERAGE_MAX_ENTRIES,
    COUNTRY_LOCALE_PROFILE_MAP,
    NAVIGATOR_LANGUAGE,
    NAVIGATOR_LANGUAGES,
    TIMEZONE_IANA,
    TIMEZONE_OFFSET_MINUTES,
    TIMEZONE_NAME,
    SCREEN_WIDTH,
    SCREEN_HEIGHT,
    HARDWARE_CONCURRENCY,
    JS_HEAP_SIZE_LIMIT,
    DEVICE_MEMORY,
    NAVIGATOR_PROTO_SAMPLES,
    DOCUMENT_KEY_SAMPLES,
    WINDOW_KEY_SAMPLES,
    WINDOW_FEATURE_FLAGS,
    build_browser_environment,
    validate_browser_profile,
    BROWSER_PROFILE_POOL,
    pick_browser_profile,
    IMPERSONATE,
    REQUEST_TIMEOUT,
)

# ---------- OpenAI Protocol ----------
from config.openai_protocol import (
    OPENAI_CLIENT_ID,
    OPENAI_SCOPE,
    OPENAI_AUDIENCE,
    OPENAI_REDIRECT_URI,
    SENTINEL_SV,
    OPENAI_BUILD_ID,
    OAI_CLIENT_BUILD_NUMBER,
    OAI_CLIENT_VERSION,
    STATSIG_CLIENT_KEY,
    STATSIG_SDK_VERSION,
    STATSIG_SDK_TYPE,
    AB_CLIENT_KEY,
    AB_SDK_VERSION,
    SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE,
    CHATGPT_ANON_BOOTSTRAP_ENABLED,
    CHATGPT_AUTH_BOOTSTRAP_ENABLED,
    CHATGPT_BOOTSTRAP_STRICT,
    OPENAI_PROXY_RETRY_MAX_ATTEMPTS,
    OPENAI_PROXY_RETRY_DELAY,
    OPENAI_PREFLIGHT_TIMEOUT,
)

# ---------- Proxy pool ----------
from config.proxy import (
    PROXY_POOL,
    PROXY_POOL_UPSTREAM_PROXY,
    PLAN_CHECK_PROXY_MODE,
    PLAN_CHECK_PROXY,
    PLAN_CHECK_UPSTREAM_PROXY,
    PLAN_CHECK_TIMEOUT,
    PLAN_CHECK_MAX_ATTEMPTS,
    PLAN_CHECK_RETRY_DELAY,
    PLAN_CHECK_REGISTRATION_RECHECK_DELAY,
    PLAN_CHECK_WORKERS,
    PLAN_CHECK_QUEUE_LIMIT,
    PLAN_CHECK_MIN_INTERVAL,
    PLAN_CHECK_JITTER,
    pick_proxy,
    PROXY,
)

# ---------- Registration defaults ----------
from config.register import (
    REGISTER_EMAIL,
    REGISTER_PASSWORD,
    REGISTER_NAME,
    AUTO_PLAN_CHECK_AFTER_REGISTER,
    PROTOCOL_REUSE_FINGERPRINT_BY_EMAIL,
    POST_REGISTER_DWELL_SECONDS_RANGE,
)

# ---------- Email service ----------
from config.email import (
    USE_EMAIL_SERVICE,
    EMAIL_SOURCE,
    OUTLOOK_ACCOUNTS_FILE,
    OUTLOOK_API_BASE,
    OTP_POLL_INTERVAL,
    OTP_MAX_WAIT,
    OTP_SETTLE_SECONDS,
    GENERIC_API_PROXY,
    EMAIL_DOMAIN,
    QQ_IMAP_SERVER,
    QQ_IMAP_PORT,
    QQ_EMAIL,
    QQ_IMAP_PASSWORD,
    GPTMAIL_API_KEY,
    MAIL_NEST_API_KEY,
    MAIL_NEST_PROJECT_CODE,
    CLOUDFLARE_API_BASE,
    CLOUDFLARE_API_KEY,
    CLOUDFLARE_AUTH_MODE,
    CLOUDFLARE_CUSTOM_AUTH,
    CLOUDFLARE_PATH_DOMAINS,
    CLOUDFLARE_PATH_ACCOUNTS,
    CLOUDFLARE_PATH_TOKEN,
    CLOUDFLARE_PATH_MESSAGES,
    CLOUDFLARE_DEFAULT_DOMAINS,
    CLOUDFLARE_REQUEST_TIMEOUT,
    CLOUDFLARE_NAME_LENGTH,
    CLOUDMAIL_API_BASE,
    CLOUDMAIL_ADMIN_EMAIL,
    CLOUDMAIL_PASSWORD,
    CLOUDMAIL_TOKEN_PATH,
    CLOUDMAIL_AUTH_TOKEN,
    CLOUDMAIL_DOMAINS,
    CLOUDMAIL_AUTO_ADD_USER,
    CLOUDMAIL_RANDOM_LOCAL_LENGTH,
    REMAIL_API_BASE,
    REMAIL_API_KEY,
    REMAIL_PROJECT_ID,
    REMAIL_EMAIL_SUFFIX,
    REMAIL_SERVICE_MODE,
    REMAIL_SUPPLY_POLICY,
    REMAIL_ORDER_WAIT_SECONDS,
    REMAIL_REQUEST_TIMEOUT,
    XIGUA_API_BASE,
    XIGUA_API_KEY,
    XIGUA_PROJECT_SLUG,
    XIGUA_OFFER_ID,
    XIGUA_REQUEST_TIMEOUT,
    XIGUA_POLL_ATTEMPTS,
    XIGUA_POLL_INTERVAL,
)

# ---------- 2FA ----------
from config.twofa import (
    ENABLE_2FA,
    TWOFA_PROXY_MODE,
    TWOFA_REAUTH_MAX_ATTEMPTS,
    TWOFA_REAUTH_RETRY_DELAY,
    TWOFA_WORKERS,
    TWOFA_QUEUE_LIMIT,
)


# ---------- Hot-reload support ----------
# WebUI After changing the config, call reload_all() to make all runtime code see the new values, without restarting the process.
# Prerequisite: runtime code must read config as `config.<submodule>.KEY` (not `from config.submodule import KEY`, which pins the value).
# For example `from config import codex; ... codex.SMS_COUNTRY`: after reload the codex module object is updated in place,
# so codex.SMS_COUNTRY immediately sees the new value.
import importlib as _importlib

_RELOADABLE_SUBMODULES = (
    "config.browser",
    "config.openai_protocol",
    "config.proxy",
    "config.register",
    "config.email",
    "config.twofa",
    "config.roxybrowser",
    "config.cloakbrowser",
    "config.browser_use",
    "config.skyvern",
    "config.flow_trigger",
    "config.codex",
    "config.extract_link",
    "config.sub2api",
    "config.humanize",
)


def reload_all() -> list[str]:
    """
    Hot-reload all config submodules and return the list of module names that reloaded successfully.
    If any submodule fails to reload (syntax error etc.) an ImportError is raised and the caller must handle it.
    """
    from config.env_loader import load_env
    load_env(override=True)

    import sys
    reloaded = []
    for name in _RELOADABLE_SUBMODULES:
        mod = sys.modules.get(name)
        if mod is None:
            mod = _importlib.import_module(name)
        else:
            _importlib.reload(mod)
        reloaded.append(name)
    # Also refresh the "pinned" constants at the top level of the config package (for the legacy `from config import X` usage)
    # Note: values read through those names are the pre-reload ones, but the submodule attribute style is unaffected.
    _refresh_top_level_constants()
    return reloaded


def _refresh_top_level_constants() -> None:
    """Copy the constants of the just-reloaded submodule to the top level of the config package again."""
    import config as _self
    from config import browser, openai_protocol, proxy as _proxy, register, email, twofa, roxybrowser, cloakbrowser, browser_use, skyvern, codex, extract_link, sub2api, humanize, flow_trigger
    # Simple and blunt: enumerate the important constants and overwrite them in _self
    for src in (browser, openai_protocol, _proxy, register, email, twofa, roxybrowser, cloakbrowser, browser_use, skyvern, codex, extract_link, sub2api, humanize, flow_trigger):
        for k in dir(src):
            if k.isupper() or k in ("pick_proxy", "pick_browser_profile", "build_browser_environment", "validate_browser_profile"):
                setattr(_self, k, getattr(src, k))


__all__ = [
    # browser
    "USER_AGENT", "CHROME_MAJOR", "CHROME_FULL_VERSION", "BROWSER_OS",
    "NAVIGATOR_PLATFORM", "NAVIGATOR_VENDOR", "USER_AGENT_DATA_PLATFORM",
    "SEC_CH_UA", "SEC_CH_UA_PLATFORM", "SEC_CH_UA_MOBILE",
    "SEC_CH_UA_FULL_VERSION_LIST", "SEC_CH_UA_PLATFORM_VERSION",
    "SEC_CH_UA_ARCH", "SEC_CH_UA_BITNESS", "SEC_CH_UA_MODEL",
    "SEND_HIGH_ENTROPY_CLIENT_HINTS", "ACCEPT_LANGUAGE", "BROWSER_LOCALE_PROFILE", "BROWSER_LOCALE_PROFILES",
    "AUTO_BROWSER_LOCALE_FROM_IP", "IP_GEO_TIMEOUT", "IP_GEO_ENDPOINTS", "REJECT_CLOUD_PROXY", "CLOUD_PROXY_ORG_KEYWORDS", "BROWSER_DATA_SAVER_MODE", "BROWSER_DATA_SAVER_DEEP_MODE", "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", "BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS", "BROWSER_TRAFFIC_DETAIL_LOG", "BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES", "BROWSER_JS_COVERAGE_LOG", "BROWSER_JS_COVERAGE_MAX_ENTRIES", "COUNTRY_LOCALE_PROFILE_MAP",
    "NAVIGATOR_LANGUAGE", "NAVIGATOR_LANGUAGES",
    "TIMEZONE_IANA", "TIMEZONE_OFFSET_MINUTES", "TIMEZONE_NAME", "SCREEN_WIDTH", "SCREEN_HEIGHT",
    "HARDWARE_CONCURRENCY", "JS_HEAP_SIZE_LIMIT", "DEVICE_MEMORY",
    "NAVIGATOR_PROTO_SAMPLES", "DOCUMENT_KEY_SAMPLES", "WINDOW_KEY_SAMPLES", "WINDOW_FEATURE_FLAGS",
    "build_browser_environment", "validate_browser_profile",
    "BROWSER_PROFILE_POOL", "pick_browser_profile",
    "IMPERSONATE", "REQUEST_TIMEOUT",
    # openai_protocol
    "OPENAI_CLIENT_ID", "OPENAI_SCOPE", "OPENAI_AUDIENCE", "OPENAI_REDIRECT_URI",
    "SENTINEL_SV", "OPENAI_BUILD_ID", "OAI_CLIENT_BUILD_NUMBER", "OAI_CLIENT_VERSION",
    "STATSIG_CLIENT_KEY", "STATSIG_SDK_VERSION", "STATSIG_SDK_TYPE", "AB_CLIENT_KEY", "AB_SDK_VERSION",
    "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", "CHATGPT_ANON_BOOTSTRAP_ENABLED", "CHATGPT_AUTH_BOOTSTRAP_ENABLED", "CHATGPT_BOOTSTRAP_STRICT",
    "OPENAI_PROXY_RETRY_MAX_ATTEMPTS", "OPENAI_PROXY_RETRY_DELAY", "OPENAI_PREFLIGHT_TIMEOUT",
    # proxy
    "PROXY_POOL", "PROXY_POOL_UPSTREAM_PROXY", "PLAN_CHECK_PROXY_MODE", "PLAN_CHECK_PROXY", "PLAN_CHECK_UPSTREAM_PROXY",
    "PLAN_CHECK_TIMEOUT", "PLAN_CHECK_MAX_ATTEMPTS", "PLAN_CHECK_RETRY_DELAY",
    "PLAN_CHECK_REGISTRATION_RECHECK_DELAY", "PLAN_CHECK_WORKERS", "PLAN_CHECK_QUEUE_LIMIT",
    "PLAN_CHECK_MIN_INTERVAL", "PLAN_CHECK_JITTER", "pick_proxy", "PROXY",
    # register
    "REGISTER_EMAIL", "REGISTER_PASSWORD", "REGISTER_NAME",
    # email
    "USE_EMAIL_SERVICE", "EMAIL_SOURCE",
    "OUTLOOK_ACCOUNTS_FILE", "OUTLOOK_API_BASE",
    "OTP_POLL_INTERVAL", "OTP_MAX_WAIT", "OTP_SETTLE_SECONDS", "GENERIC_API_PROXY",
    "EMAIL_DOMAIN", "QQ_IMAP_SERVER", "QQ_IMAP_PORT", "QQ_EMAIL", "QQ_IMAP_PASSWORD",
    "GPTMAIL_API_KEY", "MAIL_NEST_API_KEY", "MAIL_NEST_PROJECT_CODE",
    "CLOUDFLARE_API_BASE", "CLOUDFLARE_API_KEY", "CLOUDFLARE_AUTH_MODE", "CLOUDFLARE_CUSTOM_AUTH",
    "CLOUDFLARE_PATH_DOMAINS", "CLOUDFLARE_PATH_ACCOUNTS", "CLOUDFLARE_PATH_TOKEN",
    "CLOUDFLARE_PATH_MESSAGES", "CLOUDFLARE_DEFAULT_DOMAINS",
    "CLOUDFLARE_REQUEST_TIMEOUT", "CLOUDFLARE_NAME_LENGTH",
    "CLOUDMAIL_API_BASE", "CLOUDMAIL_ADMIN_EMAIL", "CLOUDMAIL_PASSWORD", "CLOUDMAIL_TOKEN_PATH",
    "CLOUDMAIL_AUTH_TOKEN", "CLOUDMAIL_DOMAINS",
    "CLOUDMAIL_AUTO_ADD_USER", "CLOUDMAIL_RANDOM_LOCAL_LENGTH",
    "REMAIL_API_BASE", "REMAIL_API_KEY", "REMAIL_PROJECT_ID", "REMAIL_EMAIL_SUFFIX", "REMAIL_SERVICE_MODE",
    "REMAIL_SUPPLY_POLICY", "REMAIL_ORDER_WAIT_SECONDS", "REMAIL_REQUEST_TIMEOUT",
    "XIGUA_API_BASE", "XIGUA_API_KEY", "XIGUA_PROJECT_SLUG", "XIGUA_OFFER_ID", "XIGUA_REQUEST_TIMEOUT",
    "XIGUA_POLL_ATTEMPTS", "XIGUA_POLL_INTERVAL",
    # twofa
    "ENABLE_2FA", "TWOFA_PROXY_MODE", "TWOFA_REAUTH_MAX_ATTEMPTS", "TWOFA_REAUTH_RETRY_DELAY",
    "TWOFA_WORKERS", "TWOFA_QUEUE_LIMIT",
]
