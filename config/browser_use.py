# -*- coding: utf-8 -*-
"""
Browser Use Cloud configuration.

docs:
- https://docs.browser-use.com/cloud/browser/stealth
- https://docs.browser-use.com/cloud/browser/playwright-puppeteer-selenium

Usage:
  1. In config/roxybrowser.py set REGISTRATION_DRIVER = "browser_use"
  2. Put BROWSER_USE_API_KEY in .env (it can also be written to .env through the WebUI secret field)
  3. Recommended: turn off Codex first:ENABLE_CODEX_AUTO = False
"""
from config.env_loader import env_str, apply_env_overrides

# Browser Use API Key(created in the Cloud Dashboard; .env / environment variables are read first)
BROWSER_USE_API_KEY: str = env_str("BROWSER_USE_API_KEY", "")

# Connection method:
#   "cdp_url" = Use the official CDP websocket directly (recommended, simplest)
#   "sdk"     = Call the REST API to create a session first (reserved; cdp_url is still used by default)
BROWSER_USE_CONNECT_MODE: str = "cdp_url"

# CDP Connect URL template. {api_key}/{proxy_country_code}/{profile_id} are substituted or appended as query parameters as needed.
BROWSER_USE_CDP_BASE: str = "wss://connect.browser-use.com"

# Optional REST API root (for later use if explicit create/stop session is adopted)
BROWSER_USE_API_BASE: str = "https://api.browser-use.com/api/v2"

# Proxy country code, two lowercase letters, e.g. jp / us / sg / de; leave empty to use the Browser Use default exit
BROWSER_USE_PROXY_COUNTRY_CODE: str = "jp"

# Whether to use the built-in Browser Use proxy. When False the cloud proxy is not forced where possible (still depends on the server default)
BROWSER_USE_USE_PROXY: bool = True

# Optional: pin a Browser Use profileId to reuse cookies/localStorage.
# For personal batch registration leave it empty so every new session is cleaner.
BROWSER_USE_PROFILE_ID: str = ""

# Playwright / page timeout
BROWSER_USE_TIMEOUT: int = 90
BROWSER_USE_NAVIGATION_TIMEOUT: int = 90

# Browser Use Cloud browser keepAlive / session lifetime (minutes).
# It is passed to Browser Use as the timeout parameter of the connect URL, so the remote browser stays alive while waiting for OTP, SMS and the callback.
# Browser Use The timeout unit is currently minutes and the official limit is usually 240; the code clamps it to 1~240.
BROWSER_USE_SESSION_TIMEOUT: int = 240

# Fast mode: reduces extra human_delay and long waits in the Browser Use flow; on by default.
BROWSER_USE_FAST_MODE: bool = True

# Stage timing log: prints the time spent on connect/goto/email/otp/phone/callback etc., which helps locate slow spots.
BROWSER_USE_LOG_TIMING: bool = True

# Maximum time spent on the profile page; after a timeout it no longer hangs and directly tries to read the accessToken from /api/auth/session.
BROWSER_USE_PROFILE_TIMEOUT: int = 28
SKYVERN_PROFILE_TIMEOUT: int = 45

# Maximum wait for reading the accessToken after the profile page finishes/times out; the task fails if it cannot be obtained.
BROWSER_USE_SESSION_ACCESS_TOKEN_TIMEOUT: int = 18
SKYVERN_SESSION_ACCESS_TOKEN_TIMEOUT: int = 35

# Whether to disconnect actively after the task ends CDP
BROWSER_USE_KEEP_BROWSER_OPEN: bool = False

# Extra CDP query parameters, merged into the connect URL; a field with the same name overrides BROWSER_USE_SESSION_TIMEOUT above.
# Example: {"timeout": "120"}  # unit: minutes
BROWSER_USE_EXTRA_QUERY: dict = {}

# Starting sign-up page to open
BROWSER_USE_START_URL: str = "https://chatgpt.com/auth/login"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'BROWSER_USE_API_KEY': 'str', 'BROWSER_USE_PROXY_COUNTRY_CODE': 'str', 'BROWSER_USE_USE_PROXY': 'bool', 'BROWSER_USE_PROFILE_ID': 'str', 'BROWSER_USE_CDP_BASE': 'str', 'BROWSER_USE_TIMEOUT': 'int', 'BROWSER_USE_SESSION_TIMEOUT': 'int', 'BROWSER_USE_FAST_MODE': 'bool', 'BROWSER_USE_LOG_TIMING': 'bool', 'BROWSER_USE_PROFILE_TIMEOUT': 'int', 'SKYVERN_PROFILE_TIMEOUT': 'int', 'BROWSER_USE_SESSION_ACCESS_TOKEN_TIMEOUT': 'int', 'SKYVERN_SESSION_ACCESS_TOKEN_TIMEOUT': 'int', 'BROWSER_USE_KEEP_BROWSER_OPEN': 'bool', 'BROWSER_USE_START_URL': 'str'})
