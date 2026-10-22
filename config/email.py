# -*- coding: utf-8 -*-
"""
Email service configuration.

Outlook Default pool behavior for registration emails and OTPs:
    1. On first start the legacy `用于注册的邮箱.txt` is migrated to SQLite
    2. While running, import and manage emails through the WebUI "Email library"
    3. Registration takes an available email directly from the SQLite email library
"""
from config.env_loader import env_str, apply_env_overrides


# True: REGISTER_EMAIL When empty, the email is obtained automatically from the Outlook account pool and the OTP is received automatically
# False: Use the flow of manual email input + manual OTP entry
USE_EMAIL_SERVICE = False

# Allowed values (several can be configured separated by English commas, used as fallbacks in order, e.g. "outlook,generic_api,mailnest,remail,xigua"):
#   "outlook"           — Purchased Outlook account pool + remote mail retrieval via mail.chatai.codes
#   "cloudflare_domain" — Cloudflare Domain email (forwarded to a QQ mailbox), mail retrieved via IMAP
#   "cloudflare" — Cloudflare Worker Temporary email (cloudflare_temp_email), created and codes fetched via API
#   "generic_api"       — Generic API code-retrieval email pool (email----code-retrieval URL)
#   "imap"              — Generic IMAP email pool (each item contains the server and login credentials)
#   "gptmail"           — GPTMail Temporary email API (emails are generated randomly at runtime and codes are received automatically)
#   "mailnest"          — MailNest/MailNest temporary email API (emails are purchased at runtime and codes are received automatically)
#   "cloudmail"         — CloudMail/Cloud Mail API(domains are obtained from the platform automatically and emails are generated randomly)
#   "remail"            — Remail Open API (orders by project and receives verification codes automatically)
#   "mailcode"          — Domain email MailCode (idempotent purchase, prepares the code-retrieval channel, receives codes by cursor)
#   "xigua"             — Xigua email code-receiving platform (orders by project and receives verification codes automatically)
EMAIL_SOURCE = "outlook,generic_api,mailnest"


# ============================================================
# Outlook mode (purchased account pool + mail retrieval service)
# ============================================================

OUTLOOK_ACCOUNTS_FILE = "用于注册的邮箱.txt"

# Outlook retrieval mode:
#   "auto"   = Use the remote mail.chatai.codes first; when the remote returns 402/DEPLOYMENT_DISABLED, automatically switch to a direct Microsoft Graph connection
#   "remote" = use the remote only mail.chatai.codes
#   "direct" = Use only a direct Microsoft Graph connection (exchange clientId + refreshToken for an access_token)
OUTLOOK_FETCH_MODE = "auto"

# Root URL of the mail retrieval API (used in remote mode)
OUTLOOK_API_BASE = "https://mail.chatai.codes"


# ============================================================
# OTP polling parameters
# ============================================================

OTP_POLL_INTERVAL = 3
OTP_MAX_WAIT = 90

# Outlook Dual-protocol retrieval: after one OTP is caught, wait this many more seconds to see whether a later email arrives.
OTP_SETTLE_SECONDS = 5

# Dedicated proxy for generic API code retrieval; it does not read the proxy pool and does not apply the proxy-pool upstream chain.
# Fill in when needed, e.g. http://127.0.0.1:7897; leave empty for a direct connection.
GENERIC_API_PROXY: str = ""

# Default inbox folder for generic IMAP emails; the server, port and credentials are imported together with the email material.
IMAP_MAILBOX = "INBOX"
# Timeout of a single IMAP network operation; after a failure it reconnects within the total OTP wait budget.
IMAP_SOCKET_TIMEOUT = 10


# ============================================================
# Cloudflare Domain email mode (forwarded to a QQ mailbox, mail retrieved via IMAP)
# ============================================================

# Your Cloudflare domain, e.g. "mydomain.com"
# Registration automatically generates random@mydomain.com as the registration email
EMAIL_DOMAIN = ""

# QQ IMAP server address of the mailbox (fixed to imap.qq.com)
QQ_IMAP_SERVER = "imap.qq.com"

# QQ mailbox IMAP port (SSL)
QQ_IMAP_PORT = 993

# QQ mailbox address (receives the emails forwarded by Cloudflare), e.g. "123456@qq.com"
QQ_EMAIL = ""

# QQ IMAP authorization code of the mailbox (generated in the QQ Mail web version -> Settings -> Account -> POP3/IMAP/SMTP service)
# Note: this is the 16-character authorization code, not the QQ password
QQ_IMAP_PASSWORD = env_str("QQ_IMAP_PASSWORD", "")


# ============================================================
# GPTMail Temporary email API (fixed address: https://mail.chatgpt.org.uk)
# ============================================================

# Required when EMAIL_SOURCE="gptmail" is selected; fill it in at WebUI "Config -> Email / OTP".
GPTMAIL_API_KEY = env_str("GPTMAIL_API_KEY", "")


# ============================================================
# Cloudflare Worker Temporary email (cloudflare_temp_email compatible)
# EMAIL_SOURCE Enabled when it contains "cloudflare"; different from cloudflare_domain (QQ IMAP).
# ============================================================

# Worker API root address, e.g. https://mail.example.com
CLOUDFLARE_API_BASE = env_str("CLOUDFLARE_API_BASE", "")

# May be left empty in anonymous mode; in admin mode fill in ADMIN_PASSWORD
CLOUDFLARE_API_KEY = env_str("CLOUDFLARE_API_KEY", "")

# none / bearer / x-api-key / x-admin-auth / query-key
CLOUDFLARE_AUTH_MODE = "none"

# Worker global password (PASSWORDS), injected into the request header x-custom-auth
CLOUDFLARE_CUSTOM_AUTH = env_str("CLOUDFLARE_CUSTOM_AUTH", "")

CLOUDFLARE_PATH_DOMAINS = "/api/domains"
CLOUDFLARE_PATH_ACCOUNTS = "/api/new_address"
CLOUDFLARE_PATH_TOKEN = "/api/token"
CLOUDFLARE_PATH_MESSAGES = "/api/mails"

# Default receiving domains; several can be separated by newlines or commas; leave empty to let the Worker decide
CLOUDFLARE_DEFAULT_DOMAINS = []

CLOUDFLARE_REQUEST_TIMEOUT = 20
CLOUDFLARE_NAME_LENGTH = 10


# ============================================================
# MailNest-MailNest Outlook temporary email:https://mailnest.top/
# ============================================================

# Required when EMAIL_SOURCE="mailnest" is selected; fill it in at WebUI "Config -> Email / OTP".
MAIL_NEST_API_KEY = env_str("MAIL_NEST_API_KEY", "")

# MailNest Project code; OpenAI/ChatGPT defaults to chatgpt001.
MAIL_NEST_PROJECT_CODE = "chatgpt001"

# ============================================================
# CloudMail API docs:https://doc.skymail.ink/api/api-doc
# ============================================================

# Cloud Mail Worker/API address, e.g.:https://mail.example.com
CLOUDMAIL_API_BASE = ""

# CloudMail Admin email/password; used to generate the Token manually, and to log in automatically to obtain domains when domains are hidden.
CLOUDMAIL_ADMIN_EMAIL = env_str("CLOUDMAIL_ADMIN_EMAIL", "")
CLOUDMAIL_PASSWORD = env_str("CLOUDMAIL_PASSWORD", "")

# CloudMail Path of the token generation endpoint; follows the Cloud Mail public API style by default.
CLOUDMAIL_TOKEN_PATH = "/api/public/genToken"

# CloudMail/Cloud Mail API Authorization Token; can be filled in manually or obtained automatically from the account and password.
CLOUDMAIL_AUTH_TOKEN = env_str("CLOUDMAIL_AUTH_TOKEN", "")

# Email domain list, one per line or separated by English commas; may be left empty and is then obtained automatically from the CloudMail platform at runtime.
CLOUDMAIL_DOMAINS = []

# Whether to call /api/public/addUser to create the mailbox user after generating an email.
CLOUDMAIL_AUTO_ADD_USER = True

# Length of the random email local-part.
CLOUDMAIL_RANDOM_LOCAL_LENGTH = 12


# ============================================================
# Remail Open API:https://remail.aishop6.com/docs
# ============================================================

# API Root address; https://remail.aishop6.com/docs is also accepted and the client normalizes it automatically.
REMAIL_API_BASE = "https://remail.aishop6.com"

# Remail API Key generated in the console, starting with rk-.
REMAIL_API_KEY = env_str("REMAIL_API_KEY", "")

# Pick, in the Remail project list, the project ID used for ChatGPT/OpenAI verification codes; project 2 is used by default.
REMAIL_PROJECT_ID = 2

# Email suffix to order for the project; outlook.com is the usual choice for Microsoft mailbox products.
REMAIL_EMAIL_SUFFIX = "outlook.com"

# code is short-lived code receiving; purchase is a long-lived purchase that can receive repeatedly, and purchase is used by default.
REMAIL_SERVICE_MODE = "purchase"

# private_first Prefer your own stock; public_only uses only public stock, and public_only is used by default.
REMAIL_SUPPLY_POLICY = "public_only"

# Maximum seconds to wait for the order details to supply the credentials when the order response does not return a service token immediately.
REMAIL_ORDER_WAIT_SECONDS = 30

# Remail HTTP request timeout.
REMAIL_REQUEST_TIMEOUT = 20

# ============================================================
# Xigua email code-receiving platform:https://xigua.dasiqo.com/
# ============================================================
XIGUA_API_BASE = "https://xigua.dasiqo.com"
XIGUA_API_KEY = env_str("XIGUA_API_KEY", "")
XIGUA_PROJECT_SLUG = "openai"
XIGUA_OFFER_ID = "off_79b957291b6eae5f53f2abd04ebda998"
XIGUA_REQUEST_TIMEOUT = 20
XIGUA_POLL_ATTEMPTS = 10
XIGUA_POLL_INTERVAL = 5

# Domain email MailCode (fixed official address, not overridable via .env)
MAILCODE_API_BASE = "https://mailcode.bzb.qzz.io"
MAILCODE_API_KEY = env_str("MAILCODE_API_KEY", "")
MAILCODE_PRODUCT_ID = "product_a3783a0ead074b4091631b9ad04153f9"
MAILCODE_REQUEST_TIMEOUT = 20
MAILCODE_CHANNEL_WAIT_SECONDS = 60

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'MAILCODE_API_KEY': 'str', 'MAILCODE_PRODUCT_ID': 'str', 'MAILCODE_REQUEST_TIMEOUT': 'int', 'MAILCODE_CHANNEL_WAIT_SECONDS': 'int', 'USE_EMAIL_SERVICE': 'bool', 'OTP_MAX_WAIT': 'int', 'OTP_POLL_INTERVAL': 'int', 'OTP_SETTLE_SECONDS': 'int', 'GENERIC_API_PROXY': 'str', 'EMAIL_SOURCE': 'str', 'IMAP_MAILBOX': 'str', 'IMAP_SOCKET_TIMEOUT': 'int', 'EMAIL_DOMAIN': 'str', 'QQ_EMAIL': 'str', 'QQ_IMAP_PASSWORD': 'str', 'GPTMAIL_API_KEY': 'str', 'OUTLOOK_FETCH_MODE': 'str', 'MAIL_NEST_API_KEY': 'str', 'MAIL_NEST_PROJECT_CODE': 'str', 'CLOUDFLARE_API_BASE': 'str', 'CLOUDFLARE_API_KEY': 'str', 'CLOUDFLARE_AUTH_MODE': 'str', 'CLOUDFLARE_CUSTOM_AUTH': 'str', 'CLOUDFLARE_PATH_DOMAINS': 'str', 'CLOUDFLARE_PATH_ACCOUNTS': 'str', 'CLOUDFLARE_PATH_TOKEN': 'str', 'CLOUDFLARE_PATH_MESSAGES': 'str', 'CLOUDFLARE_DEFAULT_DOMAINS': 'list_str_multiline', 'CLOUDFLARE_REQUEST_TIMEOUT': 'int', 'CLOUDFLARE_NAME_LENGTH': 'int', 'CLOUDMAIL_API_BASE': 'str', 'CLOUDMAIL_ADMIN_EMAIL': 'str', 'CLOUDMAIL_PASSWORD': 'str', 'CLOUDMAIL_TOKEN_PATH': 'str', 'CLOUDMAIL_AUTH_TOKEN': 'str', 'CLOUDMAIL_DOMAINS': 'list_str_multiline', 'CLOUDMAIL_AUTO_ADD_USER': 'bool', 'CLOUDMAIL_RANDOM_LOCAL_LENGTH': 'int', 'REMAIL_API_BASE': 'str', 'REMAIL_API_KEY': 'str', 'REMAIL_PROJECT_ID': 'int', 'REMAIL_EMAIL_SUFFIX': 'str', 'REMAIL_SERVICE_MODE': 'str', 'REMAIL_SUPPLY_POLICY': 'str', 'REMAIL_ORDER_WAIT_SECONDS': 'int', 'REMAIL_REQUEST_TIMEOUT': 'int', 'XIGUA_API_BASE': 'str', 'XIGUA_API_KEY': 'str', 'XIGUA_PROJECT_SLUG': 'str', 'XIGUA_OFFER_ID': 'str', 'XIGUA_REQUEST_TIMEOUT': 'int', 'XIGUA_POLL_ATTEMPTS': 'int', 'XIGUA_POLL_INTERVAL': 'int'})
