# -*- coding: utf-8 -*-
"""CloakBrowser automated registration configuration."""
from config.env_loader import apply_env_overrides

# Whether to start headless: False = show the window, True = headless.
CLOAK_HEADLESS: bool = True

# Whether to enable CloakBrowser humanize behavior.
CLOAK_HUMANIZE: bool = True

# Automatically match the timezone / language / WebRTC IP from the current exit IP.
CLOAK_GEOIP: bool = True

# Explicitly set the Cloak language / timezone; when empty they are inferred from the exit IP if CLOAK_GEOIP=True.
# For example: CLOAK_LOCALE="ja-JP", CLOAK_TIMEZONE="Asia/Tokyo".
CLOAK_LOCALE: str = ""
CLOAK_TIMEZONE: str = ""

# Whether to pass the proxy given to this project / drawn from the proxy pool on to CloakBrowser.
CLOAK_USE_PROXY: bool = True

# Pro license; leave empty to use the free binary.
CLOAK_LICENSE_KEY: str = ""

# Fixed fingerprint seed; when empty a new random fingerprint is generated on every launch.
CLOAK_FINGERPRINT_SEED: str = ""

# Persistent user directory; when empty a temporary context is used. To pin the account profile/cache, fill in something like "./cloak-profiles/default".
CLOAK_USER_DATA_DIR: str = ""

# Extra Chromium arguments, e.g. ["--fingerprint=12345"]. CLOAK_FINGERPRINT_SEED is appended automatically.
CLOAK_EXTRA_ARGS: list = []

# Timeout shared with the original Roxy Selenium flow.
CLOAK_SELENIUM_TIMEOUT: int = 90

# Keep the browser open instead of closing it automatically while debugging.
CLOAK_KEEP_BROWSER_OPEN: bool = False

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'CLOAK_HEADLESS': 'bool', 'CLOAK_HUMANIZE': 'bool', 'CLOAK_GEOIP': 'bool', 'CLOAK_LOCALE': 'str', 'CLOAK_TIMEZONE': 'str', 'CLOAK_USE_PROXY': 'bool', 'CLOAK_LICENSE_KEY': 'str', 'CLOAK_FINGERPRINT_SEED': 'str', 'CLOAK_USER_DATA_DIR': 'str', 'CLOAK_SELENIUM_TIMEOUT': 'int', 'CLOAK_KEEP_BROWSER_OPEN': 'bool'})
