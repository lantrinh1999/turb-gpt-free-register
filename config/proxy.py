# -*- coding: utf-8 -*-
"""
Proxy pool configuration

Each registration picks one random proxy, so different sids stay independent of each other and risk control cannot link them.

Protocol notes:
    - http:// / https://   HTTP(S) proxy
    - socks5://            SOCKS5(DNS resolved locally, may leak)
    - socks5h://           SOCKS5(DNS resolved on the proxy side, recommended, avoids DNS/IP mismatch)
"""
import random
from urllib.parse import quote, urlparse

from config.env_loader import apply_env_overrides


# Local proxy entry point; the actual exit region is determined by the proxy / routing rules.
# socks5h:// is recommended (DNS resolved on the proxy side) to avoid a mismatch between local DNS and the exit IP region.
PROXY_POOL = [
    "socks5://127.0.0.1:7897",
]

# Local upstream proxy used by the proxy pool. When set, the chain becomes: local upstream -> proxy-pool target proxy -> ChatGPT;
# Leave empty to use the proxy-pool target proxy directly, without starting the chained relay.
PROXY_POOL_UPSTREAM_PROXY = ""

# Plan / Plus trial eligibility checks and Codex Agent Token generation share this independent network policy,
# so batch requests are not dragged down by the temporary local proxy of the registration proxy pool, and an unconditional direct connection cannot make the exit policy spin out of control.
#   auto   = Prefer PLAN_CHECK_PROXY or the proxy pool; run direct only when no proxy is available
#   proxy  = Force PLAN_CHECK_PROXY or the proxy pool; fail with an error if they fail
#   direct = always connect directly
PLAN_CHECK_PROXY_MODE = "auto"

# Dedicated proxy for plan checks / Codex Agent Token generation. When empty, auto/proxy mode picks one from PROXY_POOL.
# The proxy may contain a username and password, so the WebUI saves it to .env.
PLAN_CHECK_PROXY = []

# Upstream proxy for plan checks / Codex Agent Token generation. When set, the chain becomes: local proxy -> dynamic proxy -> ChatGPT.
# For example http://127.0.0.1:7897; leave empty to connect to PLAN_CHECK_PROXY directly.
PLAN_CHECK_UPSTREAM_PROXY = ""

# Plan checks / Codex Agent Token generation use their own short timeout and limited retries so background jobs do not hang for long.
PLAN_CHECK_TIMEOUT = 15.0
PLAN_CHECK_MAX_ATTEMPTS = 3
PLAN_CHECK_RETRY_DELAY = 2.0

# Entitlements of a newly registered account may sync with a short delay. If the first check fails, or returns free with no trial
# Plus eligibility found yet, wait this many seconds and check once more; set to 0 to disable the recheck.
PLAN_CHECK_REGISTRATION_RECHECK_DELAY = 2.0

# Automatic, manual and batch plan checks share one background queue; Codex Agent Token uses a separate queue,
# but reuses the network mode, request start interval and random jitter configured here, so batch background requests are not too concentrated.
PLAN_CHECK_WORKERS = 3
PLAN_CHECK_QUEUE_LIMIT = 500
PLAN_CHECK_MIN_INTERVAL = 1.0
PLAN_CHECK_JITTER = 0.8


def _valid_port(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 65535


def normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    """Normalize common proxy shorthand while preserving explicit URLs."""
    text = str(value or "").strip()
    if not text or "://" in text:
        return text
    parts = text.split(":", 3)
    if len(parts) == 4 and parts[0] and _valid_port(parts[1]) and parts[2] and parts[3]:
        host, port, username, password = parts
        return f"{default_scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
    if len(parts) == 4 and parts[0] and parts[1] and parts[2] and _valid_port(parts[3]):
        username, password, host, port = parts
        return f"{default_scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
    parsed = urlparse(f"//{text}")
    try:
        port = parsed.port
    except ValueError:
        port = None
    if parsed.hostname and port:
        return f"{default_scheme}://{text}"
    return text


def normalize_proxy_list(values, default_scheme: str = "http") -> list[str]:
    """Normalize a multiline proxy list and omit empty entries."""
    if values is None:
        return []
    if isinstance(values, str):
        values = values.splitlines()
    return [
        normalized
        for value in values
        if (normalized := normalize_proxy_url(value, default_scheme=default_scheme))
    ]


def pick_proxy() -> str:
    """Pick a random proxy URL from the proxy pool; returns an empty string if the pool is empty (meaning no proxy)."""
    return random.choice(PROXY_POOL) if PROXY_POOL else ""


# Compatibility entry point: by default one proxy is picked at random per process start and used as the fixed proxy for the whole registration run
PROXY = pick_proxy()

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'PROXY_POOL': 'list_str_multiline',
    'PROXY_POOL_UPSTREAM_PROXY': 'str',
    'PLAN_CHECK_PROXY_MODE': 'str',
    'PLAN_CHECK_PROXY': 'list_str_multiline',
    'PLAN_CHECK_UPSTREAM_PROXY': 'str',
    'PLAN_CHECK_TIMEOUT': 'float',
    'PLAN_CHECK_MAX_ATTEMPTS': 'int',
    'PLAN_CHECK_RETRY_DELAY': 'float',
    'PLAN_CHECK_REGISTRATION_RECHECK_DELAY': 'float',
    'PLAN_CHECK_WORKERS': 'int',
    'PLAN_CHECK_QUEUE_LIMIT': 'int',
    'PLAN_CHECK_MIN_INTERVAL': 'float',
    'PLAN_CHECK_JITTER': 'float',
})
PROXY_POOL = normalize_proxy_list(PROXY_POOL)
PLAN_CHECK_PROXY = normalize_proxy_list(PLAN_CHECK_PROXY)
PROXY = pick_proxy()
