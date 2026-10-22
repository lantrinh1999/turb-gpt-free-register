# -*- coding: utf-8 -*-
"""Skyvern cloud browser configuration."""
from config.env_loader import env_str, apply_env_overrides

# Skyvern API Key(created in the Skyvern Cloud Dashboard; .env / environment variables are read first)
SKYVERN_API_KEY: str = env_str("SKYVERN_API_KEY", "")

# Skyvern API root URL. Cloud default:https://api.skyvern.com
SKYVERN_API_BASE: str = "https://api.skyvern.com"

# Browser Session creation parameters
SKYVERN_BROWSER_SESSION_TIMEOUT: int = 60  # minutes
SKYVERN_BROWSER_PROFILE_ID: str = ""
SKYVERN_PROXY_LOCATION: str = ""  # Optional: jp is converted to RESIDENTIAL_JP automatically; leave empty to omit
SKYVERN_GENERATE_BROWSER_PROFILE: bool = False
SKYVERN_AD_BLOCKER: bool = True
SKYVERN_BROWSER_TYPE: str = "stealth-chromium"

# Playwright / Page timeout; when empty the flow still uses the default timeout in the Browser Use config
SKYVERN_KEEP_BROWSER_OPEN: bool = False

# Skyvern When manual registration is not easily banned, the automation defaults stay as close to "manual operation" as possible:
# - Do not use the fast mode of Browser Use;
# - Do not additionally override UA / language / timezone / Client Hints;
# - Keep the slower character-by-character typing, the pause before clicking and the dwell after submitting.
SKYVERN_HUMAN_MODE: bool = True

# Starting sign-up page to open
SKYVERN_START_URL: str = "https://chatgpt.com/auth/login"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'SKYVERN_API_KEY': 'str',
    'SKYVERN_API_BASE': 'str',
    'SKYVERN_BROWSER_SESSION_TIMEOUT': 'int',
    'SKYVERN_BROWSER_PROFILE_ID': 'str',
    'SKYVERN_PROXY_LOCATION': 'str',
    'SKYVERN_GENERATE_BROWSER_PROFILE': 'bool',
    'SKYVERN_AD_BLOCKER': 'bool',
    'SKYVERN_BROWSER_TYPE': 'str',
    'SKYVERN_KEEP_BROWSER_OPEN': 'bool',
    'SKYVERN_HUMAN_MODE': 'bool',
    'SKYVERN_START_URL': 'str',
})
