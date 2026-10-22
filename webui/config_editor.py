# -*- coding: utf-8 -*-
"""
Config read/write layer (used by the WebUI /api/config).

Design principles:
    1. Whitelist: only expose switches / values / defaults that are "safe at runtime"; protocol-level constants
       (client_id / scope / sentinel version etc.) are never opened up, so one edit cannot kill accounts.
    2. All WebUI-editable items are written uniformly to `.env` in the project root, and `config/*.py` is no longer modified.
    3. `config/*.py` Only defaults are kept; at runtime they are overridden with `.env` through config.env_loader.
    4. When reading, `.env` takes priority, and the defaults parsed from `config/*.py` are the fallback when it is missing.
"""
import ast
import os
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_DIR = _PROJECT_ROOT / "config"
EXPLICIT_EMPTY_LIST_KEYS = {
    "PROXY_POOL",
}
EXPLICIT_EMPTY_STRING_KEYS = {
    "GENERIC_API_PROXY",
}


# ============================================================
# Whitelist: every editable item declares which file it is in, its key name, type, group and description
# type decides the front-end control + the literal format when writing back:
#   bool   -> True/False
#   int    -> integer
#   str    -> quoted string
#   list_str_multiline -> Multi-line string list (dedicated to PROXY_POOL, replaced as a whole block)
# ============================================================

EDITABLE_FIELDS = [
    # ---- WebUI Authorization ----
    {
        "key": "WEBUI_AUTH_CODE", "file": "codex.py", "type": "str", "group": "WebUI Authorization",
        "label": "WebUI Authorization Code", "help": "Only saved in .env (WEBUI_AUTH_CODE) so it does not show up on the process command line; takes effect after restarting the WebUI after saving",
        "storage": "env", "secret": True,
    },
    {
        "key": "WEBUI_SESSION_SECRET", "file": "codex.py", "type": "str", "group": "WebUI Authorization",
        "label": "Session signing key", "help": "Optional, saved in .env (WEBUI_SESSION_SECRET); when empty it is derived from the fixed authorization code, and changing the authorization code invalidates existing logins",
        "storage": "env", "secret": True,
    },
    # ---- Feature Switches ----
    {
        "key": "ENABLE_CODEX_AUTO", "file": "codex.py", "type": "bool", "group": "Feature Switches",
        "label": "Enable Codex OAuth", "help": "Automatically run the Codex authorization after a successful registration (brand new session + code receiving), persisting codex-email.json",
    },
    {
        "key": "REGISTRATION_DRIVER", "file": "roxybrowser.py", "type": "str", "group": "Registration Method",
        "label": "Registration Driver", "help": "roxy is recommended by default; protocol = pure protocol, easily gets accounts banned and is not recommended; roxy=RoxyBrowser; cloak=CloakBrowser; browser_use=Browser Use Cloud+Playwright;skyvern=Skyvern Browser Sessions+Playwright",
    },
    {
        "key": "AUTO_PLAN_CHECK_AFTER_REGISTER", "file": "register.py", "type": "bool", "group": "Registration Method",
        "label": "Auto Plan Check After Registration", "help": "Automatically queue a plan / Plus eligibility check after a successful registration; when off, the account is only saved and the plan is not checked automatically",
    },
    {
        "key": "PROTOCOL_REUSE_FINGERPRINT_BY_EMAIL", "file": "register.py", "type": "bool", "group": "Registration Method",
        "label": "Keep Protocol Fingerprint Per Email", "help": "Only affects pure-protocol registration; when on, repeated tasks for the same email reuse a stable device fingerprint, and when off every task creates a brand new fingerprint",
    },

    # ---- CloakBrowser ----
    {
        "key": "CLOAK_HEADLESS", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Cloak Headless", "help": "True=Run headless; False = show the browser window",
    },
    {
        "key": "CLOAK_HUMANIZE", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Cloak Humanized Behavior", "help": "Enable CloakBrowser humanize mouse / keyboard / scroll behavior",
    },
    {
        "key": "CLOAK_GEOIP", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Cloak Locate By Exit", "help": "Automatically match the timezone / language / WebRTC IP from the current exit IP; supports an explicit proxy or the system proxy/VPN",
    },
    {
        "key": "CLOAK_LOCALE", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Cloak Language", "help": "Leave empty for automatic; for Japan use ja-JP, for the US use en-US",
    },
    {
        "key": "CLOAK_TIMEZONE", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Cloak Timezone", "help": "Leave empty for automatic; for Japan use Asia/Tokyo, for the US use America/Los_Angeles",
    },
    {
        "key": "CLOAK_USE_PROXY", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Cloak Use Proxy", "help": "Pass the proxy given to this project or drawn from the proxy pool on to CloakBrowser",
    },
    {
        "key": "CLOAK_LICENSE_KEY", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Cloak License", "help": "Pro license; leave empty to use the free binary",
    },
    {
        "key": "CLOAK_FINGERPRINT_SEED", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Cloak Fingerprint Seed", "help": "Leave empty for random each time; a fixed value keeps the same fingerprint",
    },
    {
        "key": "CLOAK_USER_DATA_DIR", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Cloak User Directory", "help": "Leave empty to use a temporary context; fill in a path to persist cookies/cache",
    },
    {
        "key": "CLOAK_SELENIUM_TIMEOUT", "file": "cloakbrowser.py", "type": "int", "group": "CloakBrowser",
        "label": "Cloak timeout", "help": "Page and element wait timeout, in seconds",
    },
    {
        "key": "CLOAK_KEEP_BROWSER_OPEN", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Keep Cloak Browser", "help": "Enable while debugging; the browser is not closed automatically after the task ends",
    },

    # ---- Browser Use Cloud ----
    {
        "key": "BROWSER_USE_API_KEY", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "Browser Use API Key", "help": "Saved in .env (BROWSER_USE_API_KEY), not written back config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "BROWSER_USE_PROXY_COUNTRY_CODE", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "Proxy Country Code", "help": "Two-letter country code, e.g. jp/us/sg; works with the built-in Browser Use residential proxy",
    },
    {
        "key": "BROWSER_USE_USE_PROXY", "file": "browser_use.py", "type": "bool", "group": "Browser Use",
        "label": "Use Built-in Proxy", "help": "True=connection parameters carry proxyCountryCode; False = do not force the country proxy parameter",
    },
    {
        "key": "BROWSER_USE_PROFILE_ID", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "Profile ID", "help": "Optional. When filled, the cookies/localStorage of the Browser Use profile are reused; leave empty for batches",
    },
    {
        "key": "BROWSER_USE_CDP_BASE", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "CDP Address", "help": "default wss://connect.browser-use.com",
    },
    {
        "key": "BROWSER_USE_TIMEOUT", "file": "browser_use.py", "type": "int", "group": "Browser Use",
        "label": "Operation Timeout (seconds)", "help": "Playwright default operation timeout",
    },
    {
        "key": "BROWSER_USE_SESSION_TIMEOUT", "file": "browser_use.py", "type": "int", "group": "Browser Use",
        "label": "Cloud keepAlive (minutes)", "help": "Passed to the timeout/keepAlive of the Browser Use connect URL; the program limits it to 1-240 automatically, recommended 240",
    },
    {
        "key": "BROWSER_USE_FAST_MODE", "file": "browser_use.py", "type": "bool", "group": "Browser Use",
        "label": "Fast Mode", "help": "Reduces extra Browser Use waits and humanize delays; recommended on, can be turned off when troubleshooting",
    },
    {
        "key": "BROWSER_USE_LOG_TIMING", "file": "browser_use.py", "type": "bool", "group": "Browser Use",
        "label": "Timing Log", "help": "Print the time spent in each Browser Use stage: connect, open page, email, OTP, phone,callback",
    },
    {
        "key": "BROWSER_USE_KEEP_BROWSER_OPEN", "file": "browser_use.py", "type": "bool", "group": "Browser Use",
        "label": "Keep Remote Session", "help": "When debugging, browser.close() may be skipped; default False",
    },
    {
        "key": "BROWSER_USE_START_URL", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "Start URL", "help": "default https://chatgpt.com/auth/login",
    },

    # ---- Skyvern Cloud Browser ----
    {
        "key": "SKYVERN_API_KEY", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Skyvern API Key", "help": "Saved in .env (SKYVERN_API_KEY), used to create Skyvern Browser Session",
        "storage": "env", "secret": True,
    },
    {
        "key": "SKYVERN_API_BASE", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "API Address", "help": "default https://api.skyvern.com",
    },
    {
        "key": "SKYVERN_BROWSER_SESSION_TIMEOUT", "file": "skyvern.py", "type": "int", "group": "Skyvern",
        "label": "Session Timeout (minutes)", "help": "Passed in when creating a Skyvern Browser Session timeout",
    },
    {
        "key": "SKYVERN_BROWSER_PROFILE_ID", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Browser Profile ID", "help": "Optional, reuse Skyvern browser profile",
    },
    {
        "key": "SKYVERN_PROXY_LOCATION", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Proxy Region", "help": "Short codes such as jp/us/gb can be entered; they are converted to Skyvern enums automatically, e.g. jp -> RESIDENTIAL_JP; leave empty to omit",
    },
    {
        "key": "SKYVERN_BROWSER_TYPE", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Browser Type", "help": "Skyvern Skyvern supports msedge / chrome / stealth-chromium; the old value chromium-headful is converted automatically to stealth-chromium",
    },
    {
        "key": "SKYVERN_AD_BLOCKER", "file": "skyvern.py", "type": "bool", "group": "Skyvern",
        "label": "Ad Blocking", "help": "Enable ad_blocker when creating a Skyvern Browser Session ad_blocker",
    },
    {
        "key": "SKYVERN_GENERATE_BROWSER_PROFILE", "file": "skyvern.py", "type": "bool", "group": "Skyvern",
        "label": "Save Browser Profile", "help": "Session Whether Skyvern generates/saves a browser profile when the session ends browser profile",
    },
    {
        "key": "SKYVERN_KEEP_BROWSER_OPEN", "file": "skyvern.py", "type": "bool", "group": "Skyvern",
        "label": "Keep Browser", "help": "Can be enabled while debugging so the Skyvern Browser Session is not closed after the task ends Skyvern Browser Session",
    },
    {
        "key": "SKYVERN_START_URL", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Start URL", "help": "default https://chatgpt.com/auth/login",
    },
    {
        "key": "ROXY_API_BASE", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Roxy API Address", "help": "Default http://127.0.0.1:50000; must be enabled in the API settings of the Roxy app",
    },
    {
        "key": "ROXY_API_TOKEN", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Roxy API Key", "help": "Saved in .env (ROXY_API_TOKEN), not written back to config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "ROXY_PROFILE_ID", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Roxy environment ID", "help": "The Roxy browser environment / Profile ID to open; when empty, a temporary environment is tried to be created",
    },
    {
        "key": "ROXY_WORKSPACE_ID", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Roxy Workspace ID", "help": "Required when creating one environment per account; submitted to the Roxy Create Profile API as workspaceId",
    },
    {
        "key": "ROXY_PROJECT_ID", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Roxy Project ID", "help": "Obtained from project_details.projectId of /browser/workspace; submitted as projectId when creating a Profile",
    },
    {
        "key": "ROXY_WORKSPACE_LIST_PATH", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Get Team Endpoint", "help": "Default /browser/workspace; this path is tried first when fetching teams/projects, then common compatible paths automatically",
    },
    {
        "key": "ROXY_OPEN_PATH", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Open Endpoint Path", "help": "Default /browser/open; adjust here if your Roxy version differs",
    },
    {
        "key": "ROXY_CREATE_INTERVAL", "file": "roxybrowser.py", "type": "float", "group": "RoxyBrowser",
        "label": "Environment Creation Interval", "help": "Minimum interval between adjacent /browser/create requests with multiple threads, default 1.5 seconds; set to 0 to disable",
    },
    {
        "key": "ROXY_OPEN_HEADLESS", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Headless Window Start", "help": "Pass headless to /browser/open when opening a Roxy environment; False = show the window, True = start headless",
    },
    {
        "key": "ROXY_CLOSE_PATH", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Close Endpoint Path", "help": "default /browser/close",
    },
    {
        "key": "ROXY_KEEP_BROWSER_OPEN", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Keep Browser", "help": "Enable while debugging; the Roxy environment is not closed automatically after the task ends",
    },
    {
        "key": "ROXY_ONE_PROFILE_PER_ACCOUNT", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "One Environment Per Account", "help": "Every account is forced to create a new Roxy Profile, which is closed and deleted after use; reusing a fixed environment is forbidden",
    },
    {
        "key": "ROXY_DELETE_PROFILE_AFTER_RUN", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Delete Environment After Finish", "help": "In one-environment-per-account mode, delete the Roxy Profile created in this round after the task ends Roxy Profile",
    },
    {
        "key": "ROXY_RANDOM_OS_ON_CREATE", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Random Environment Creation OS", "help": "When creating a Roxy environment, Windows / macOS is picked at random each time, not fixed macOS",
    },
    {
        "key": "ROXY_RANDOM_OS_CHOICES", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Random OS Range", "help": "Comma-separated, default Windows,macOS; Roxy supports Windows / macOS / Linux / IOS / Android",
    },
    {
        "key": "ROXY_RANDOM_PROFILE_NAME_ON_CREATE", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Random Environment Name", "help": "When creating a Roxy environment, a different name is generated automatically, avoiding the fixed gpt-free-register",
    },
    {
        "key": "ROXY_PROFILE_NAME_PREFIX", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Random Name Prefix", "help": "Default rb; the actual name format is like rb-timestamp-randomcode",
    },
    {
        "key": "ROXY_CREATE_USE_PROXY_POOL", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Use Proxy Pool For Environments", "help": "When creating a Roxy environment, one proxy is picked at random from the 'Proxy pool' on the config page and written to Roxy proxyInfo",
    },
    {
        "key": "ROXY_PROXY_CHECK_CHANNEL", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Proxy Check Channel", "help": "Written to Roxy proxyInfo.checkChannel; omitted when empty, default IPRust.io",
    },
    {
        "key": "ROXY_DELETE_PATH", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Delete Endpoint Path", "help": "Default /browser/delete; adjust if your Roxy version differs",
    },
    {
        "key": "CODEX_OAUTH_DRIVER", "file": "codex.py", "type": "str", "group": "Codex",
        "label": "Codex Authorization Driver", "help": "roxy is recommended by default; protocol = original protocol authorization; roxy = use RoxyBrowser; cloak = use CloakBrowser; browser_use = use Browser Use Cloud; skyvern = use Skyvern; same_as_registration = follow the registration driver",
    },
    {
        "key": "ROXY_CODEX_CALLBACK_TIMEOUT", "file": "roxybrowser.py", "type": "int", "group": "RoxyBrowser",
        "label": "Codex Callback Timeout", "help": "Roxy Codex OAuth Maximum seconds to wait for the localhost:1455 callback",
    },
    {
        "key": "ENABLE_2FA", "file": "twofa.py", "type": "bool", "group": "Feature Switches",
        "label": "Enable 2FA(TOTP)", "help": "Set up a one-time password automatically after registration completes (one more OTP email is received)",
    },
    {
        "key": "TWOFA_PROXY_MODE", "file": "twofa.py", "type": "str", "group": "Feature Switches",
        "label": "2FA Proxy Mode", "help": "saved=Prefer the proxy saved with the account; pool = ignore the saved proxy and pick one from the proxy pool each time; restart the service after changing",
        "choices": [
            {"value": "saved", "label": "Use the proxy saved with the account"},
            {"value": "pool", "label": "Pick one from the proxy pool each time"},
        ],
    },
    {
        "key": "TWOFA_WORKERS", "file": "twofa.py", "type": "int", "group": "Feature Switches",
        "label": "2FA Concurrency", "help": "Number of 2FA setup tasks run at the same time, default 4, range 1-16; takes effect immediately after saving",
    },
    {
        "key": "TWOFA_QUEUE_LIMIT", "file": "twofa.py", "type": "int", "group": "Feature Switches",
        "label": "2FA Queue Capacity", "help": "Total number of 2FA tasks allowed to be queued and running, default 200; takes effect immediately after saving",
    },
    {
        "key": "ENABLE_FLOW_TRIGGER", "file": "flow_trigger.py", "type": "bool", "group": "Feature Switches",
        "label": "Enable Flow Trigger", "help": "Automatically call the internal Flow API after a successful registration (does not affect the registration result)",
    },
    {
        "key": "ENABLE_HUMANIZE_DELAY", "file": "humanize.py", "type": "bool", "group": "Human Pacing",
        "label": "Enable Random Pauses", "help": "Add random waits between steps such as registration, OTP and authorization, closer to human operation pacing",
    },
    {
        "key": "HUMANIZE_DELAY_FACTOR", "file": "humanize.py", "type": "float", "group": "Human Pacing",
        "label": "Pause Multiplier", "help": "Overall multiplier of the random pauses; 1.0 = default, 0.5 = halved, 2.0 = doubled",
    },
    {
        "key": "ENABLE_HUMANIZE_BROWSER_ACTIONS", "file": "humanize.py", "type": "bool", "group": "Human Pacing",
        "label": "Randomized Browser Actions", "help": "Roxy/Cloak Roxy/Cloak clicks, typing and page observation use random mouse landing points and character-by-character typing, reducing mechanical traces",
    },
    # ---- Email / OTP ----
    {
        "key": "USE_EMAIL_SERVICE", "file": "email.py", "type": "bool", "group": "Email / OTP",
        "label": "Auto Claim Email + Receive Code", "help": "True=True = claim an email from the email pool automatically and receive the OTP automatically; False = manual mode: use REGISTER_EMAIL and type the OTP by hand on the task page",
    },
    {
        "key": "REGISTER_EMAIL", "file": "register.py", "type": "str", "group": "Email / OTP",
        "label": "Manual Registration Email", "help": "USE_EMAIL_SERVICE=False Required when USE_EMAIL_SERVICE=False. For example your outlook.com address; read the OTP in the web mailbox and submit it back on the task page",
    },
    {
        "key": "REGISTER_NAME", "file": "register.py", "type": "str", "group": "Email / OTP",
        "label": "Display Name", "help": "Leave empty to generate an English name automatically",
    },
    {
        "key": "OTP_MAX_WAIT", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "OTP Max Wait (seconds)", "help": "Maximum seconds to wait for the verification code email; the task fails on timeout",
    },
    {
        "key": "OTP_POLL_INTERVAL", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "OTP Poll Interval (seconds)", "help": "How many seconds between checks for new emails",
    },
    {
        "key": "GENERIC_API_PROXY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Generic API Code Retrieval Proxy", "help": "Only used for generic_api code retrieval; it does not read the registration proxy pool and does not apply the proxy-pool upstream chain; leave empty for a direct connection, for example http://127.0.0.1:7897",
        "storage": "env",
    },
    {
        "key": "EMAIL_SOURCE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Email Source", "help": "One or several, comma-separated and used as fallbacks in order:outlook,generic_api,imap,cloudflare_domain,cloudflare,gptmail,mailnest,cloudmail,remail,xigua,mailcode",
    },
    {
        "key": "IMAP_MAILBOX", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Generic IMAP Inbox", "help": "Default folder of generic IMAP emails, normally INBOX; the server, port, username and password are imported with the email pool",
    },
    {
        "key": "GPTMAIL_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "GPTMail API Key", "help": "Required when the gptmail email source is selected; saved in .env and not written into the config source",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDFLARE_API_BASE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare API Address", "help": "Worker Root address of the temporary email API, e.g. https://mail.example.com; required when cloudflare is selected",
        "storage": "env",
    },
    {
        "key": "CLOUDFLARE_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare API Key", "help": "May be empty in anonymous mode; in admin mode fill in ADMIN_PASSWORD; saved in .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDFLARE_AUTH_MODE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare Auth Mode", "help": "none / bearer / x-api-key / x-admin-auth / query-key",
    },
    {
        "key": "CLOUDFLARE_CUSTOM_AUTH", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare global password", "help": "Worker PASSWORDS, injected into x-custom-auth; saved in .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDFLARE_PATH_ACCOUNTS", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare Create Path", "help": "Default /api/new_address; commonly for admin /admin/new_address",
    },
    {
        "key": "CLOUDFLARE_PATH_MESSAGES", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare Mail Path", "help": "default /api/mails",
    },
    {
        "key": "CLOUDFLARE_PATH_DOMAINS", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare Domain Path", "help": "Default /api/domains (reserved)",
    },
    {
        "key": "CLOUDFLARE_PATH_TOKEN", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare Token Path", "help": "Default /api/token (reserved as a fallback)",
    },
    {
        "key": "CLOUDFLARE_DEFAULT_DOMAINS", "file": "email.py", "type": "list_str_multiline", "group": "Email / OTP",
        "label": "Cloudflare Default Domains", "help": "Receiving domains, one per line or comma-separated; used in rotation when creating, may be left empty",
    },
    {
        "key": "CLOUDFLARE_REQUEST_TIMEOUT", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Cloudflare Request Timeout (seconds)", "help": "HTTP request timeout, default 20",
    },
    {
        "key": "CLOUDFLARE_NAME_LENGTH", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Cloudflare Random Name Prefix Length", "help": "admin Length of the local-part when creating, default 10",
    },
    {
        "key": "OUTLOOK_FETCH_MODE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Outlook Retrieval Mode", "help": "auto=Remote first, automatically switching to a direct Graph connection on remote 402/DEPLOYMENT_DISABLED; direct = only use a direct Microsoft Graph connection; remote = only use the remote service",
    },
    {
        "key": "EMAIL_DOMAIN", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Forwarding Domain (cloudflare_domain)", "help": "Only used by cloudflare_domain: the Email Routing domain, e.g. mydomain.com; unrelated to EMAIL_SOURCE=cloudflare",
    },
    {
        "key": "QQ_EMAIL", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "QQ Mailbox Address", "help": "Only cloudflare_domain: the QQ mailbox that receives the Email Routing forwards, e.g. 123456@qq.com",
    },
    {
        "key": "QQ_IMAP_PASSWORD", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "QQ Mailbox IMAP Authorization Code", "help": "Only cloudflare_domain: the QQ IMAP authorization code, saved in .env and not written back config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "MAIL_NEST_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "MailNest API Key", "help": "Required when the mailnest email source is selected; saved in .env and not written into the config source",
        "storage": "env", "secret": True,
    },
    {
        "key": "MAIL_NEST_PROJECT_CODE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "MailNest Project Code", "help": "Project code, default chatgpt001, get it at mailnest.top/buy-email",
    },
    {
        "key": "CLOUDMAIL_API_BASE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "CloudMail API Address", "help": "Cloud Mail Worker/API address, e.g. https://mail.example.com",
    },
    {
        "key": "CLOUDMAIL_ADMIN_EMAIL", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "CloudMail Admin Email", "help": "Used to generate the Token; also used to log in and read the domains when the platform hides them",
        "storage": "env",
    },
    {
        "key": "CLOUDMAIL_PASSWORD", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "CloudMail Password", "help": "Used to obtain the Token automatically; saved in .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDMAIL_TOKEN_PATH", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "CloudMail Token Path", "help": "/api/public/genToken is always used; it can be changed if your deployment version differs",
    },
    {
        "key": "CLOUDMAIL_AUTH_TOKEN", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "CloudMail Token", "help": "CloudMail/Cloud Mail API Authorization Token; saved in .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDMAIL_DOMAINS", "file": "email.py", "type": "list_str_multiline", "group": "Email / OTP",
        "label": "CloudMail Domain List", "help": "May be left empty; it is fetched from the platform automatically at runtime. You can also click 'Get CloudMail domains' to cache it here",
    },
    {
        "key": "CLOUDMAIL_AUTO_ADD_USER", "file": "email.py", "type": "bool", "group": "Email / OTP",
        "label": "CloudMail Auto Create User", "help": "After a random email is generated, call /api/public/addUser to create the user",
    },
    {
        "key": "CLOUDMAIL_RANDOM_LOCAL_LENGTH", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "CloudMail Random Name Prefix Length", "help": "Length of the generated email local-part, recommended 10-16",
    },
    {
        "key": "MAILCODE_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "MailCode API Key", "help": "Create it on the API keys page of the official site; it needs purchase and read permissions and the key is saved in .env; the service address is fixed to the official site",
        "external_url": "https://mailcode.bzb.qzz.io",
        "external_label": "Open Official Site",
        "storage": "env", "secret": True,
    },
    {
        "key": "MAILCODE_PRODUCT_ID", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "MailCode product ID", "help": "The id returned by /api/open/v1/products; each registration task buys only one email and does not switch products automatically",
    },
    {
        "key": "MAILCODE_REQUEST_TIMEOUT", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "MailCode Request Timeout (seconds)", "help": "Timeout of a single HTTP request, default 20 seconds",
    },
    {
        "key": "MAILCODE_CHANNEL_WAIT_SECONDS", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "MailCode Channel Preparation Timeout (seconds)", "help": "After purchase, initialize IMAP first and wait for READY before handing the email to the registration flow; default 60 seconds",
    },
    {
        "key": "REMAIL_API_BASE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Remail API Address", "help": "Default https://remail.aishop6.com; the docs address can also be entered https://remail.aishop6.com/docs",
        "external_url": "https://remail.aishop6.com/register?aff=AFFLGYQMTYIXH",
        "external_label": "Open Remail Official Site",
    },
    {
        "key": "REMAIL_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Remail API Key", "help": "Remail API Key generated in the console, starting with rk-; required when the remail source is selected, saved in .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "REMAIL_PROJECT_ID", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Remail Project ID", "help": "Remail API The projectId in the project list, used to match the ChatGPT/OpenAI verification code project",
    },
    {
        "key": "REMAIL_EMAIL_SUFFIX", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Remail Email Suffix", "help": "The email suffix used when ordering, default outlook.com; do not enter a full email",
    },
    {
        "key": "REMAIL_SERVICE_MODE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Remail Service Mode", "help": "code=short-lived code receiving; purchase = long-lived purchase (can receive repeatedly, default)",
    },
    {
        "key": "REMAIL_SUPPLY_POLICY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Remail Stock Policy", "help": "private_first Prefer your own stock; public_only only uses public stock (default)",
    },
    {
        "key": "REMAIL_ORDER_WAIT_SECONDS", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Remail Order Wait (seconds)", "help": "When no service token is returned right after ordering, wait for the order to supply the credentials, default 30 seconds",
    },
    {
        "key": "REMAIL_REQUEST_TIMEOUT", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Remail Request Timeout (seconds)", "help": "Remail API Timeout of a single HTTP request, default 20 seconds",
    },
    {
        "key": "XIGUA_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Xigua API Key", "help": "Xigua API key, required when the xigua source is selected, saved in .env",
        "storage": "env", "secret": True,
        "external_url": "https://xigua.dasiqo.com/#register?invite=XGMKWMW4Z7",
        "external_label": "Open Xigua Official Site",
    },
    {
        "key": "XIGUA_OFFER_ID", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Xigua Offer ID", "help": "Manually fill in the Xigua project plan offer_id",
    },
    {
        "key": "XIGUA_REQUEST_TIMEOUT", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Xigua Request Timeout (seconds)", "help": "Timeout of a single HTTP request of the Xigua API, default 20 seconds",
    },
    {
        "key": "XIGUA_POLL_ATTEMPTS", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Xigua Poll Count", "help": "Maximum number of requests per wait for a verification code, default 10",
    },
    {
        "key": "XIGUA_POLL_INTERVAL", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Xigua Poll Interval (seconds)", "help": "Interval of each Xigua verification code query, default 5 seconds",
    },
    # ---- Browser Region Profile ----
    {
        "key": "BROWSER_LOCALE_PROFILE", "file": "browser.py", "type": "str", "group": "Browser Profile",
        "label": "Region Profile", "help": "Should match the proxy exit region; options jp/cn/us/sg. The current local proxy was measured as Tokyo, Japan, recommended jp",
    },

    {
        "key": "AUTO_BROWSER_LOCALE_FROM_IP", "file": "browser.py", "type": "bool", "group": "Browser Profile",
        "label": "Auto Profile By Exit IP", "help": "When on, every BrowserSession picks the language/timezone from the current proxy exit IP automatically; on failure it falls back to the region profile",
    },
    {
        "key": "IP_GEO_TIMEOUT", "file": "browser.py", "type": "float", "group": "Browser Profile",
        "label": "IP Locate Timeout (seconds)", "help": "Timeout of a single request of the exit IP geolocation API; a failure falls back automatically and does not affect registration",
    },
    {
        "key": "BROWSER_DATA_SAVER_MODE", "file": "browser.py", "type": "bool", "group": "Browser Profile",
        "label": "Local browser traffic-saving mode", "help": "Only Roxy/Cloak block optional resources and block the configured background download domains through the local proxy relay; not enabled for Browser Use/Skyvern; off by default",
    },
    {
        "key": "BROWSER_DATA_SAVER_BLOCKED_PROXY_HOSTS", "file": "browser.py", "type": "list_str_multiline", "group": "Browser Profile",
        "label": "Traffic-Saving Proxy Domain Block", "help": "Only effective when traffic-saving mode is on and the local browser proxy relay is used; blocks startup/background downloads before connecting upstream. One domain per line (subdomains included), default dl.google.com, gvt1.com; enter [] to disable, do not enter URLs or paths",
    },
    {
        "key": "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", "file": "browser.py", "type": "list_str_multiline", "group": "Browser Profile",
        "label": "Local browser traffic-saving block types", "help": "Only effective for Roxy/Cloak; one per line, default image, media; options stylesheet, font, manifest, texttrack. Do not enter script/xhr/fetch/document/websocket",
    },
    {
        "key": "BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS", "file": "browser.py", "type": "list_str_multiline", "group": "Browser Profile",
        "label": "Local browser traffic-saving URL block rules", "help": "Only effective for Roxy/Cloak; one URL glob per line; by default RUM/ad analytics and Google GSI (when Google sign-in is not used) are blocked. Do not block core APIs/sentinel; enter [] to disable the default rules",
    },
    {
        "key": "BROWSER_TRAFFIC_DETAIL_LOG", "file": "browser.py", "type": "bool", "group": "Browser Profile",
        "label": "Local browser traffic detail log", "help": "Only effective for Roxy/Cloak; at the end of registration outputs the URL, type, method, status code and upload/download size of every resource; URL query values are masked; off by default",
    },
    {
        "key": "BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES", "file": "browser.py", "type": "int", "group": "Browser Profile",
        "label": "Max Traffic Detail Entries", "help": "Output sorted by total bytes per request in descending order, default 2000, max 10000; used to analyze blockable resources later",
    },
    {
        "key": "BROWSER_JS_COVERAGE_LOG", "file": "browser.py", "type": "bool", "group": "Browser Profile",
        "label": "Record local browser JS coverage", "help": "Only effective for Roxy/Cloak; records the JS functions and offsets actually executed in this registration through Chrome CDP; not enabled for Browser Use/Skyvern; off by default",
    },
    {
        "key": "BROWSER_JS_COVERAGE_MAX_ENTRIES", "file": "browser.py", "type": "int", "group": "Browser Profile",
        "label": "Max entries of local browser JS coverage", "help": "Only effective for Roxy/Cloak; maximum number of executed functions written to the log, which also limits the number of saved script summaries, default 1000, max 10000",
    },

    # ---- Proxy pool ----
    {
        "key": "PROXY_POOL", "file": "proxy.py", "type": "list_str_multiline", "group": "Proxy pool",
        "label": "Proxy Pool (one per line)", "help": "One proxy URL per line, blank lines are ignored; when empty no proxy is used",
        "recommended_links": [
            {
                "label": "IPWO Residential",
                "url": "https://www.ipwo.net/?code=XEP358YGZ",
                "description": "IPWO Residential proxies cover residential IP resources in 195+ countries and regions, support multi-region network environments, and suit AI applications, browser automation, overseas service access and data collection. Highlight: 2GB of dynamic residential traffic is granted with no threshold,",
                "description_link_label": "Claim Entry",
                "description_link_url": "https://www.ipwo.net/?code=XEP358YGZ",
                "description_after_link": "; join the group for occasional IP perks.",
            },
            {
                "label": "IPRocket Residential",
                "url": "https://iprocket.io?viteCode=1PVNyLuJ",
                "description": "Good value residential proxies; contact the author via TG to buy traffic",
            },
            {
                "label": "Rola-IP Residential",
                "url": "https://rola-ip.co/?code=0326C5HA",
                "description": "Roxy High-quality residential proxies from a partner, with a 15% discount on registration",
            },
        ],
    },
    {
        "key": "PROXY_POOL_UPSTREAM_PROXY", "file": "proxy.py", "type": "str", "group": "Proxy pool",
        "label": "Proxy Pool Upstream Proxy", "help": "Optional; every target proxy of the proxy pool connects through this local upstream. Leave empty for no chaining. The address is shown in plain text and only saved to .env",
        "storage": "env",
    },
    {
        "key": "PLAN_CHECK_PROXY_MODE", "file": "proxy.py", "type": "str", "group": "Proxy pool",
        "label": "Plan/Agent Network Mode", "help": "Used for plan checks and Agent Token generation; auto = use the proxy if the local proxy is available, connect directly if nothing is listening; proxy = force the proxy; direct = force a direct connection",
    },
    {
        "key": "PLAN_CHECK_PROXY", "file": "proxy.py", "type": "list_str_multiline", "group": "Proxy pool",
        "label": "Plan/Agent Dedicated Proxy (one per line)", "help": "Used for plan checks, liveness checks and Agent Token generation; dynamic proxy URLs are supported, one per line. Only saved to .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "PLAN_CHECK_UPSTREAM_PROXY", "file": "proxy.py", "type": "str", "group": "Proxy pool",
        "label": "Plan/Agent Local Upstream Proxy", "help": "Optional; only for the plan/Agent dedicated proxy, forming the chain 'local proxy -> dynamic proxy -> ChatGPT”proxy chain. Leave empty for no chaining. The address is shown in plain text. Only saved to .env",
        "storage": "env",
    },
    {
        "key": "PLAN_CHECK_TIMEOUT", "file": "proxy.py", "type": "float", "group": "Proxy pool",
        "label": "Plan/Agent Timeout (seconds)", "help": "Timeout of a single request of plan checks and Agent Token generation, recommended 10-20 seconds; independent of the registration request timeout",
    },
    {
        "key": "PLAN_CHECK_MAX_ATTEMPTS", "file": "proxy.py", "type": "int", "group": "Proxy pool",
        "label": "Plan/Agent Max Attempts", "help": "Retry count of plan checks and Agent Token generation on 403, 429, 5xx or network errors, recommended 3",
    },
    {
        "key": "PLAN_CHECK_RETRY_DELAY", "file": "proxy.py", "type": "float", "group": "Proxy pool",
        "label": "Plan/Agent Retry Interval (seconds)", "help": "Retry interval of plan checks and Agent Token generation, growing with the attempt count; the server Retry-After takes priority",
    },
    {
        "key": "PLAN_CHECK_REGISTRATION_RECHECK_DELAY", "file": "proxy.py", "type": "float", "group": "Proxy pool",
        "label": "New Account Eligibility Recheck Delay (seconds)", "help": "A newly registered free account is rechecked once when no trial eligibility is found or the first check failed; 0 means off",
    },
    {
        "key": "PLAN_CHECK_WORKERS", "file": "proxy.py", "type": "int", "group": "Proxy pool",
        "label": "Plan Check Concurrency", "help": "Shared by automatic, manual and batch plan checks; Agent Token generation uses a separate queue; 2-4 threads recommended",
    },
    {
        "key": "PLAN_CHECK_QUEUE_LIMIT", "file": "proxy.py", "type": "int", "group": "Proxy pool",
        "label": "Plan Check Queue Limit", "help": "Prevents unlimited pile-up from abnormal batch operations, recommended 100-1000",
    },
    {
        "key": "PLAN_CHECK_MIN_INTERVAL", "file": "proxy.py", "type": "float", "group": "Proxy pool",
        "label": "Plan/Agent Min Request Interval (seconds)", "help": "Limits the request start frequency of plan checks and Agent Token generation, lowering the 429 risk",
    },
    {
        "key": "PLAN_CHECK_JITTER", "file": "proxy.py", "type": "float", "group": "Proxy pool",
        "label": "Plan/Agent Request Random Jitter (seconds)", "help": "Adds a random delay on top of the minimum interval of plan checks and Agent Token generation, so requests are not too regular",
    },
    # ---- Link Extraction ----
    {
        "key": "EXTRACT_LINK_API_BASE", "file": "extract_link.py", "type": "str", "group": "Link Extraction",
        "label": "Link extraction service address", "help": "Fill in the link extraction service API address",
    },
    {
        "key": "EXTRACT_LINK_CDK", "file": "extract_link.py", "type": "str", "group": "Link Extraction",
        "label": "Link Extraction CDK", "help": "Used for creating link extraction tasks and listening to task events; a successful extraction deducts 1 use",
        "storage": "env", "secret": True,
    },
    {
        "key": "EXTRACT_LINK_TYPE", "file": "extract_link.py", "type": "str", "group": "Link Extraction",
        "label": "Link Type", "help": "Supports pix / upi / kakao_pay / ideal",
    },
    {
        "key": "EXTRACT_LINK_WORKERS", "file": "extract_link.py", "type": "int", "group": "Link Extraction",
        "label": "Link Concurrency", "help": "Number of background threads for batch link extraction, recommended 1-4",
    },
    # ---- Codex Config ----
    {
        "key": "SUB2API_AUTO_EXPORT", "file": "sub2api.py", "type": "bool", "group": "Codex",
        "label": "Agent sub2 Auto Sync", "help": "Automatically sync to sub2api after a Codex Agent Token is generated successfully sub2api",
    },
    {
        "key": "SUB2API_SYNC_MODE", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "Agent sub2 Sync Mode", "help": "api=direct upload API; file = write a local json; both = API + local json",
    },
    {
        "key": "SUB2API_API_BASE", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "sub2 API Base URL", "help": "sub2api Service address; shared by Agent Token upload and Codex OAuth, for example http://127.0.0.1:8080",
    },
    {
        "key": "SUB2API_API_KEY", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "sub2 API Key", "help": "sub2api Management API Key; the request header uses x-api-key; if empty no auth header is sent", "storage": "env", "secret": True,
    },
    {
        "key": "SUB2API_API_TIMEOUT", "file": "sub2api.py", "type": "int", "group": "Codex",
        "label": "sub2 timeout", "help": "sub2api Request timeout in seconds",
    },
    {
        "key": "SUB2API_OUTPUT_PATH", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "Agent sub2 Local Path", "help": "Only used when SUB2API_SYNC_MODE=file/both; a relative path is resolved against the project root",
    },
    {
        "key": "SUB2API_PROXY_KEY", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "Agent sub2 Proxy Key", "help": "Optional; written to account.proxy_key, and used to initialize when proxies is empty proxies[0].proxy_key",
    },
    # ---- Code-Receiving Platform ----
    # ---- Codex: base / CPA / sub2api settings ----
    {
        "key": "CODEX_AUTH_URL_SOURCE", "file": "codex.py", "type": "str", "group": "Codex",
        "label": "Authorization URL Source", "help": "cpa=CPA generated by CPA and uploaded to CPA; sub2 = generated by sub2 and uploaded to sub2; local = local PKCE",
    },
    {
        "key": "CPA_MANAGEMENT_URL", "file": "codex.py", "type": "str", "group": "Codex",
        "label": "CPA Management Address", "help": "For example http://localhost:8317/admin/oauth; the program takes the origin and calls /v0/management/*",
    },
    {
        "key": "CPA_MANAGEMENT_KEY", "file": "codex.py", "type": "str", "group": "Codex",
        "label": "Management Key", "help": "Saved in .env (CPA_MANAGEMENT_KEY), not written back to config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "CPA_REQUEST_TIMEOUT", "file": "codex.py", "type": "int", "group": "Codex",
        "label": "CPA Timeout (seconds)", "help": "Timeout of requests to the CPA management API",
    },
    {
        "key": "CPA_SAVE_CALLBACK_RECEIPT", "file": "codex.py", "type": "bool", "group": "Codex",
        "label": "Save CPA Receipt", "help": "CPA When CPA does not return the complete authorization file, a callback submission record is still saved locally",
    },

    {
        "key": "SMS_PROVIDER", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "Code-Receiving Channel", "help": "grizzly / smsbower / l / h; smsbower uses the SMSBower handler_api, l/h use the local number service",
    },
    {
        "key": "SMS_COUNTRY", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "Country Code", "help": "The country passed to the code-receiving platform; for SMSBower fill it in per its country table, for GrizzlySMS the US is commonly 187; for the H channel it is used as the country of H_API.md country",
    },
    {
        "key": "SMS_SERVICE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "Service/Project Code", "help": "GrizzlySMS/L/SMSBower as service; for OpenAI (ChatGPT) on SMSBower dr is recommended, and openai/chatgpt is converted automatically by the program; for the H channel it is used as projectId",
    },
    {
        "key": "SMS_MAX_PRICE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "Max Number Price", "help": "Passed through to maxPrice of the code-receiving platform; leave empty for unlimited. SMSBower can use it to filter price / number tier",
    },
    {
        "key": "SMS_MAX_RETRIES", "file": "codex.py", "type": "int", "group": "Code-Receiving Platform",
        "label": "Number Switch Retries", "help": "When a number receives no SMS or is rejected by OpenAI, switch to the next number; the maximum number of retries",
    },
    {
        "key": "SMS_CODE_WAIT", "file": "codex.py", "type": "int", "group": "Code-Receiving Platform",
        "label": "Per-Number SMS Wait (seconds)", "help": "Maximum seconds one number waits for an SMS to arrive; on timeout the number is switched",
    },
    {
        "key": "SMS_API_KEY", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "GrizzlySMS API Key", "help": "GrizzlySMS platform API Key, saved in .env (SMS_API_KEY), not written back config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "SMSBOWER_API_BASE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "SMSBower API Address", "help": "default https://smsbower.page/stubs/handler_api.php",
    },
    {
        "key": "SMSBOWER_API_KEY", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "SMSBower API Key", "help": "SMSBower Console API Key, saved in .env, not written back to config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "SMSBOWER_USE_V2", "file": "codex.py", "type": "bool", "group": "Code-Receiving Platform",
        "label": "SMSBower Use V2 Number Taking", "help": "The official client docs use getNumber; normally keep it off. Only enable it after confirming the account supports getNumberV2",
    },
    {
        "key": "SMSBOWER_PROVIDER_IDS", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "SMSBower Supplier Filter", "help": "Optional, supplier IDs separated by commas; leave empty to let the platform choose automatically",
    },
    {
        "key": "SMSBOWER_EXCEPT_PROVIDER_IDS", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "SMSBower Exclude Suppliers", "help": "Optional, excluded supplier IDs separated by commas",
    },
    {
        "key": "SMSBOWER_PHONE_EXCEPTION", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "SMSBower Exclude Number Prefixes", "help": "Optional, number prefixes separated by commas; used to avoid known unusable number ranges",
    },
    {
        "key": "SMSBOWER_MIN_PRICE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "SMSBower Minimum Price", "help": "Optional, passes minPrice through; together with the maximum price it limits the number price range",
    },
    {
        "key": "H_API_BASE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "H API Address", "help": "H Base address of the number service, e.g. http://localhost:8788",
    },
    {
        "key": "H_ADMIN_AUTH_CODE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "H Authorization Code", "help": "Saved in .env (H_ADMIN_AUTH_CODE), not written back config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "H_PHONE_PREFIX", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "H Number Prefix", "help": "H Fill in when the number returned by H has no country code, e.g. enter 1 for a US 10-digit local number; leave empty to add none",
    },
    {
        "key": "H_PHONE_ACQUIRE_MODE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "H Taking Method", "help": "reusable=Prefer reusing historical available numbers; new = take a new number every time",
    },
    {
        "key": "L_API_BASE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "L API Address", "help": "L Base address of the number service, e.g. http://localhost:8788",
    },
    {
        "key": "L_ADMIN_AUTH_CODE", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "L Authorization Code", "help": "Saved in .env (L_ADMIN_AUTH_CODE), not written back config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "L_PHONE_PREFIX", "file": "codex.py", "type": "str", "group": "Code-Receiving Platform",
        "label": "L Number Prefix", "help": "L Fill in when the number returned by H has no country code, e.g. enter 1 for a US 10-digit local number; leave empty to add none",
    },
]

_FIELD_BY_KEY = {f["key"]: f for f in EDITABLE_FIELDS}


# ============================================================
# Read: parse the source to get the current value (no import, to avoid caching/side effects)
# ============================================================

def _config_path(filename: str) -> Path:
    path = (_CONFIG_DIR / filename).resolve()
    # Prevent directory traversal: it must be under config/
    if _CONFIG_DIR not in path.parents:
        raise ValueError(f"Invalid config path: {filename}")
    return path


def _literal_default_from_expr(node):
    """Take the "source default value" from the assignment expression as far as possible, without executing module code.

    Compatible:
      KEY = "literal"
      KEY: str = env_str("KEY", "default")
      KEY = env_bool("KEY", True)
      KEY = env_value("KEY", 123, "int")
    """
    try:
        return ast.literal_eval(node)
    except Exception:
        pass

    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # env_str/env_bool/env_int/env_float/env_list the second positional argument is the default value.
        if func_name in {"env_str", "env_bool", "env_int", "env_float", "env_list"}:
            if len(node.args) >= 2:
                try:
                    return ast.literal_eval(node.args[1])
                except Exception:
                    return None
            return None

        # env_value(key, default, vtype)
        if func_name == "env_value" and len(node.args) >= 2:
            try:
                return ast.literal_eval(node.args[1])
            except Exception:
                return None

    return None


def _find_assignment_value_node(source: str, key: str):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for t in targets:
            if isinstance(t, ast.Name) and t.id == key:
                return node.value
    return None


def _parse_value_from_source(source: str, key: str, vtype: str):
    """Parse the current value of KEY from the source. Returns None on failure."""
    if vtype == "list_str_multiline":
        # Parse the whole module with the AST and take the list literal of this assignment
        value_node = _find_assignment_value_node(source, key)
        if value_node is None:
            return None
        try:
            val = ast.literal_eval(value_node)
            if isinstance(val, (list, tuple)):
                return [str(x) for x in val]
        except (ValueError, SyntaxError):
            return None
        return None

    # Scalars: prefer the AST for the default value, so env_str("KEY", "") is not treated as an ordinary string.
    value_node = _find_assignment_value_node(source, key)
    if value_node is not None:
        value = _literal_default_from_expr(value_node)
        if value is not None:
            return value

    # AST Fall back to the old regex parsing when it fails.
    m = re.search(
        rf"^{re.escape(key)}\s*(?::[^=\n]+)?=\s*(.+?)\s*(?:#.*)?$",
        source, re.MULTILINE,
    )
    if not m:
        return None
    raw = m.group(1).strip()
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return raw


def _parse_env_typed_value(raw: str, fallback, vtype: str):
    """Convert the .env string by field type; fall back to fallback on failure."""
    from config.env_loader import env_value
    return env_value("__NO_SUCH_ENV_KEY__", fallback, vtype) if raw is None else _coerce_raw_value(raw, fallback, vtype)


def _coerce_raw_value(raw: str, fallback, vtype: str):
    try:
        if raw is None or str(raw).strip() == "":
            return fallback
        if vtype == "bool":
            return str(raw).strip().lower() in ("true", "1", "yes", "on", "y")
        if vtype == "int":
            return int(str(raw).strip())
        if vtype == "float":
            return float(str(raw).strip())
        if vtype == "list_str_multiline":
            text = str(raw)
            try:
                val = ast.literal_eval(text)
                if isinstance(val, (list, tuple)):
                    return [str(x).strip() for x in val if str(x).strip()]
            except Exception:
                pass
            return [line.strip() for line in text.splitlines() if line.strip()]
        return str(raw)
    except Exception:
        return fallback


def get_config() -> list[dict]:
    """Return the current values + metadata of all editable items, for the front end to render the form.

    `.env` / environment variables are read first; when not configured, fall back to the `config/*.py` defaults.
    """
    from config.env_loader import load_env, read_env_file
    load_env(override=True)
    env_file_values = read_env_file()

    out = []
    for field in EDITABLE_FIELDS:
        key = field["key"]
        path = _config_path(field["file"])
        source = path.read_text(encoding="utf-8") if path.exists() else ""
        fallback = _parse_value_from_source(source, key, field["type"])

        if key in env_file_values:
            raw_env_value = env_file_values[key]
            if field["type"] == "list_str_multiline" and key in EXPLICIT_EMPTY_LIST_KEYS and str(raw_env_value).strip() == "":
                value = []
            elif field["type"] == "str" and key in EXPLICIT_EMPTY_STRING_KEYS and str(raw_env_value).strip() == "":
                value = ""
            else:
                value = _coerce_raw_value(raw_env_value, fallback, field["type"])
        elif os.getenv(key) is not None:
            raw_env_value = os.getenv(key, "")
            if field["type"] == "str" and key in EXPLICIT_EMPTY_STRING_KEYS and str(raw_env_value).strip() == "":
                value = ""
            else:
                value = _coerce_raw_value(raw_env_value, fallback, field["type"])
        else:
            value = fallback

        if field["type"] in ("str", "list_str_multiline"):
            value = _normalize_config_value(value, field["type"])
        item = dict(field)
        item["storage"] = "env"
        item["value"] = value
        out.append(item)
    return out


# ============================================================
# Write: always write .env, never modify config/*.py
# ============================================================


_PLACEHOLDER_EMPTY = {
    "", "-", "—", "无", "空", "none", "null", "n/a", "na", "Not set", "未配置",
}


def _normalize_config_value(value, vtype: str):
    """Normalize the front-end / historical placeholder empty values, to avoid '-' being treated as a real setting."""
    if vtype == "str":
        s = "" if value is None else str(value).strip()
        if s.lower() in {x.lower() for x in _PLACEHOLDER_EMPTY}:
            return ""
        return s
    if vtype == "list_str_multiline":
        if value is None:
            return []
        if isinstance(value, str):
            lines = value.splitlines()
        elif isinstance(value, (list, tuple)):
            lines = list(value)
        else:
            lines = [str(value)]
        out = []
        for item in lines:
            s = str(item or "").strip()
            if not s or s.lower() in {x.lower() for x in _PLACEHOLDER_EMPTY}:
                continue
            out.append(s)
        return out
    return value


def _format_literal(value, vtype: str) -> str:
    """Format the value sent by the front end into a Python literal string."""
    if vtype == "bool":
        if isinstance(value, str):
            value = value.strip().lower() in ("true", "1", "yes", "on")
        return "True" if value else "False"
    if vtype == "int":
        return str(int(value))
    if vtype == "float":
        return repr(float(value))
    if vtype == "str":
        s = str(value)
        # Use repr to guarantee safe escaping, but unify it into the double-quote style
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise ValueError(f"_format_literal Unsupported type: {vtype}")


def _replace_scalar(source: str, key: str, literal: str) -> str:
    """Replace `KEY[: type] = old value` the right-hand value of the line, keeping the inline comment and the type annotation."""
    pattern = re.compile(
        rf"^(?P<head>{re.escape(key)}\s*(?::[^=\n]+)?=\s*)"
        rf"(?P<val>.+?)"
        rf"(?P<tail>\s*(?:#.*)?)$",
        re.MULTILINE,
    )
    if not pattern.search(source):
        raise ValueError(f"No replaceable assignment found in the source: {key}")
    return pattern.sub(lambda m: f"{m.group('head')}{literal}{m.group('tail')}", source, count=1)


def _replace_proxy_pool(source: str, lines: list[str]) -> str:
    """Replace the PROXY_POOL = [ ... ] list literal as a whole block (keeping the preceding assignment head)."""
    items = [ln.strip() for ln in lines if ln.strip()]
    if items:
        body = "\n".join(
            '    "' + it.replace("\\", "\\\\").replace('"', '\\"') + '",'
            for it in items
        )
        literal = "[\n" + body + "\n]"
    else:
        literal = "[]"

    # Match PROXY_POOL = [ ... ] (including across lines); locating the start/end offsets with the AST is the most reliable
    tree = ast.parse(source)
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else []
        )
        for t in targets:
            if isinstance(t, ast.Name) and t.id == "PROXY_POOL":
                src_lines = source.splitlines(keepends=True)
                start = node.value.lineno          # the line of the value ([),1-based
                end = node.value.end_lineno        # the line of the value (]),1-based
                col = node.value.col_offset         # [ the column offset in the start line
                # Keep the content before [ on the start line (that is "PROXY_POOL = " or "PROXY_POOL: list = ")
                prefix = src_lines[start - 1][:col]
                # Keep the content after ] on the end line (inline comment / newline)
                end_line = src_lines[end - 1]
                suffix = end_line[node.value.end_col_offset:]
                new_lines = (
                    src_lines[: start - 1]
                    + [prefix + literal + suffix]
                    + src_lines[end:]
                )
                return "".join(new_lines)
    raise ValueError("PROXY_POOL assignment not found")


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _format_env_value(value, vtype: str, fallback=None) -> str:
    """Format the front-end value into a string suitable for writing to .env."""
    if value is None:
        value = fallback
    if vtype == "bool":
        if isinstance(value, str):
            value = value.strip().lower() in ("true", "1", "yes", "on", "y")
        return "True" if value else "False"
    if vtype == "int":
        try:
            return str(int(value))
        except (TypeError, ValueError):
            return str(int(fallback)) if fallback is not None else "0"
    if vtype == "float":
        try:
            return repr(float(value))
        except (TypeError, ValueError):
            return repr(float(fallback)) if fallback is not None else "0.0"
    if vtype == "list_str_multiline":
        lines = _normalize_config_value(value, vtype)
        return "\n".join(lines) if lines else "[]"
    if vtype == "str":
        return _normalize_config_value(value, vtype)
    return "" if value is None else str(value)


def update_config(updates: dict) -> dict:
    """Batch update the config. All WebUI-editable items are only written to the project root `.env`."""
    from config.env_loader import write_env_values, load_env

    updated, ignored = [], []
    env_updates: dict[str, str] = {}
    current_values = {
        item["key"]: item.get("value")
        for item in get_config()
    }

    for key, value in updates.items():
        field = _FIELD_BY_KEY.get(key)
        if field is None:
            ignored.append(key)
            continue
        choices = field.get("choices") or []
        if choices:
            allowed = {str(item.get("value")) for item in choices}
            if str(value) not in allowed:
                raise ValueError(f"{key} has an invalid value, options:{', '.join(sorted(allowed))}")
        env_updates[key] = _format_env_value(
            value,
            field["type"],
            fallback=current_values.get(key),
        )
        updated.append(key)


    env_updated = write_env_values(env_updates) if env_updates else []
    if env_updated:
        load_env(override=True)

    return {"updated": updated, "ignored": ignored, "env_updated": env_updated}
