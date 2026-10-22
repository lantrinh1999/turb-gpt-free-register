# -*- coding: utf-8 -*-
"""
RoxyBrowser fingerprint browser automated registration configuration.

Official docs:
- API default host: http://127.0.0.1:50000
- All API request headers must carry the token
- Can be driven by Selenium / Puppeteer / Playwright automation
"""
from config.env_loader import env_str, apply_env_overrides


# Registration driver:
#   "protocol"     = Original curl_cffi pure-protocol registration (accounts get banned easily, not recommended)
#   "roxy"         = Call the RoxyBrowser fingerprint browser + Selenium automated registration
#   "cloak"        = Call the CloakBrowser + Playwright/Selenium adapter layer registration
#   "browser_use"  = Browser Use Cloud stealth Chromium + Playwright
#   "skyvern"      = Skyvern Browser Sessions + Playwright
REGISTRATION_DRIVER: str = "roxy"

# RoxyBrowser local API
ROXY_API_BASE: str = "http://127.0.0.1:50100"
ROXY_API_TOKEN: str = env_str("ROXY_API_TOKEN", "")

# Roxy Environment/Profile ID; when empty, a temporary environment is created first using ROXY_PROFILE_CREATE_* (if the API supports it)
ROXY_PROFILE_ID: str = ""

# Roxy Workspace ID. Roxy requires workspaceId when creating a Profile, so it must be filled in.
# It can be found on the Roxy workspace/team page or in the API response.
ROXY_WORKSPACE_ID: str = "90143"

# Roxy Project ID. /browser/workspace returns project_details.projectId; it is submitted together when creating a Profile.
ROXY_PROJECT_ID: str = "97471"

# Path of the team/workspace list endpoint. If it differs between versions it can be changed in the WebUI; the client also tries several common paths automatically.
ROXY_WORKSPACE_LIST_PATH: str = "/browser/workspace"
ROXY_WORKSPACE_LIST_METHOD: str = "GET"

# Endpoint path templates. If your version differs, only change them here.
# {profile_id} will be replaced with ROXY_PROFILE_ID.
ROXY_OPEN_PATH: str = "/browser/open"
ROXY_CLOSE_PATH: str = "/browser/close"
ROXY_CREATE_PATH: str = "/browser/create"

# Endpoint methods: open/close are usually GET; if your version requires POST, change it in the WebUI / config.
ROXY_OPEN_METHOD: str = "POST"
ROXY_CLOSE_METHOD: str = "POST"
ROXY_CREATE_METHOD: str = "POST"

# Whether to start headless when opening the browser:
#   False = Show the Roxy browser window (convenient for observing/debugging)
#   True  = Start headless without showing a window (if the current Roxy version supports headless)
ROXY_OPEN_HEADLESS: bool = False

# Extra arguments when opening the browser; merged into the /browser/open request body and take precedence over the defaults.
ROXY_OPEN_EXTRA_PARAMS: dict = {}

# Selenium behavior
ROXY_SELENIUM_TIMEOUT: int = 90
ROXY_KEEP_BROWSER_OPEN: bool = False

# Roxy Cross-Profile local static resource cache (only caches JS/CSS/font/image; auth/API always go online).
# It is enabled automatically once config.browser.BROWSER_DATA_SAVER_MODE is on, so this switch does not need to be changed separately.
ROXY_LOCAL_ASSET_CACHE_ENABLED: bool = False
ROXY_LOCAL_ASSET_CACHE_MODE: str = "auto"
ROXY_LOCAL_ASSET_CACHE_DIR: str = "./cache/roxy-assets"
ROXY_LOCAL_ASSET_CACHE_MAX_AGE: int = 86400
ROXY_LOCAL_ASSET_CACHE_MAX_ITEM_BYTES: int = 25 * 1024 * 1024

# Roxy API transient Error retry. The create endpoint is not retried by default, to avoid creating orphan environments again after a timeout; open/close/delete are retried.
ROXY_API_RETRIES: int = 3
ROXY_API_RETRY_DELAY: int = 2
ROXY_CREATE_RETRIES: int = 3
ROXY_CREATE_RETRY_DELAY: int = 3

# With multi-threaded registration, the start interval (seconds) of /browser/create requests shared by all workers.
# Roxy While the previous environment is still being created it may return "creating in progress"; staggered by 1.5 seconds by default.
ROXY_CREATE_INTERVAL: float = 1.5

# Environment lifecycle:
#   True  = One account per environment: every account is forced to create a new Profile, which is closed and deleted after use and never reused ROXY_PROFILE_ID
#   False = ROXY_PROFILE_ID can be reused, or the profile is only closed and not deleted
ROXY_ONE_PROFILE_PER_ACCOUNT: bool = True

# Whether to delete the Profile after one-account-per-environment finishes. Keeping True is recommended.
ROXY_DELETE_PROFILE_AFTER_RUN: bool = True

# Path/method of the delete-environment endpoint; if your Roxy version differs, only change it here.
ROXY_DELETE_PATH: str = "/browser/delete"
ROXY_DELETE_METHOD: str = "POST"

# Random OS fingerprint when creating a Roxy environment; when enabled every /browser/create picks one of Windows / macOS at random,
# avoiding a fixed macOS fingerprint.
ROXY_RANDOM_OS_ON_CREATE: bool = True
ROXY_RANDOM_OS_CHOICES: str = "Windows,macOS"

# Random name when creating a Roxy environment; when enabled it overrides the fixed name in ROXY_PROFILE_CREATE_PAYLOAD.
ROXY_RANDOM_PROFILE_NAME_ON_CREATE: bool = True
ROXY_PROFILE_NAME_PREFIX: str = "rb"

# Default OS fingerprint when creating a Roxy environment. Only used when ROXY_RANDOM_OS_ON_CREATE=False.
# Roxy Official os enum: Windows / macOS / Linux / IOS / Android.
ROXY_DEFAULT_OS: str = "macOS"
# Leave empty to use the default/latest version of the corresponding Roxy OS; fill in 15.3.2, 14.7 etc. to pin one.
ROXY_DEFAULT_OS_VERSION: str = ""

# Whether to use PROXY_POOL of config/proxy.py when creating a Roxy environment:
#   False = Do not set a proxy for the Roxy environment
#   True  = On every environment creation pick one proxy from PROXY_POOL at random and write it into proxyInfo
ROXY_CREATE_USE_PROXY_POOL: bool = False

# Roxy proxy check channel; leave empty to omit checkChannel.
ROXY_PROXY_CHECK_CHANNEL: str = "IPRust.io"

# Minimal payload for creating an environment when there is no ROXY_PROFILE_ID; adjust the fields to your Roxy version.
# ROXY_RANDOM_PROFILE_NAME_ON_CREATE is on by default, so the name here is only a fallback value.
ROXY_PROFILE_CREATE_PAYLOAD: dict = {
    "name": "gpt-free-register",
    "os": "macOS",
}


# Roxy Codex maximum seconds to wait for the authorization callback
ROXY_CODEX_CALLBACK_TIMEOUT: int = 180

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'REGISTRATION_DRIVER': 'str', 'ROXY_API_BASE': 'str', 'ROXY_API_TOKEN': 'str', 'ROXY_PROFILE_ID': 'str', 'ROXY_WORKSPACE_ID': 'str', 'ROXY_PROJECT_ID': 'str', 'ROXY_WORKSPACE_LIST_PATH': 'str', 'ROXY_OPEN_PATH': 'str', 'ROXY_OPEN_HEADLESS': 'bool', 'ROXY_CLOSE_PATH': 'str', 'ROXY_KEEP_BROWSER_OPEN': 'bool', 'ROXY_API_RETRIES': 'int', 'ROXY_API_RETRY_DELAY': 'int', 'ROXY_CREATE_RETRIES': 'int', 'ROXY_CREATE_RETRY_DELAY': 'int', 'ROXY_LOCAL_ASSET_CACHE_ENABLED': 'bool', 'ROXY_LOCAL_ASSET_CACHE_MODE': 'str', 'ROXY_LOCAL_ASSET_CACHE_DIR': 'str', 'ROXY_LOCAL_ASSET_CACHE_MAX_AGE': 'int', 'ROXY_LOCAL_ASSET_CACHE_MAX_ITEM_BYTES': 'int', 'ROXY_ONE_PROFILE_PER_ACCOUNT': 'bool', 'ROXY_DELETE_PROFILE_AFTER_RUN': 'bool', 'ROXY_RANDOM_OS_ON_CREATE': 'bool', 'ROXY_RANDOM_OS_CHOICES': 'str', 'ROXY_RANDOM_PROFILE_NAME_ON_CREATE': 'bool', 'ROXY_PROFILE_NAME_PREFIX': 'str', 'ROXY_CREATE_USE_PROXY_POOL': 'bool', 'ROXY_PROXY_CHECK_CHANNEL': 'str', 'ROXY_DELETE_PATH': 'str', 'ROXY_CODEX_CALLBACK_TIMEOUT': 'int', 'ROXY_CREATE_INTERVAL': 'float'})
