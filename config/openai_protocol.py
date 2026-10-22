# -*- coding: utf-8 -*-
"""
OpenAI / ChatGPT OAuth protocol fixed parameters

From packet captures; OpenAI own client_id is a fixed value.
SENTINEL_SV is the version number of sdk.js; it changes as OpenAI updates,
when updating, look up the current version at https://sentinel.openai.com/sentinel/<version>/sdk.js.
"""
from config.env_loader import apply_env_overrides

# OAuth client ID (fixed)
OPENAI_CLIENT_ID = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"

# OAuth scopes
OPENAI_SCOPE = (
    "openid email profile offline_access "
    "model.request model.read "
    "organization.read organization.write"
)

# OAuth audience
OPENAI_AUDIENCE = "https://api.openai.com/v1"

# OAuth callback (chatgpt.com side)
OPENAI_REDIRECT_URI = "https://chatgpt.com/api/auth/callback/openai"

# Sentinel SDK Version number (affects the sentinel iframe URL and the referer header)
SENTINEL_SV = "20260810913b"

# ChatGPT Page build identifier (used for Sentinel p[6] / documentElement data-build simulation)
OPENAI_BUILD_ID = "prod-d4e40d432de549a66bf9feb61d43c262b258386f"

# ChatGPT Front-end CES / API reporting headers, from the 2026-07-19 capture.
OAI_CLIENT_BUILD_NUMBER = "10762726"
OAI_CLIENT_VERSION = OPENAI_BUILD_ID

# Statsig / Analytics SDK version, used by the pure protocol flow to fill in the front-end equivalent chain.
STATSIG_CLIENT_KEY = "client-nb0qtYlZuy2tCMN5s5ncnuIBCJncjRViT0IzFm7GqST"
STATSIG_SDK_VERSION = "3.33.1"
STATSIG_SDK_TYPE = "javascript-client"
AB_CLIENT_KEY = "client-tN5GMyzpIPKXd3KNv7ANIfiqjRSvNNTTWbZdbdabF58"
AB_SDK_VERSION = "3.32.7"

# 2026-09-14 Roxy In successful samples email-otp/validate carries both Sentinel and SO.
SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE = True

# Whether to fill in the ChatGPT Web first-screen bootstrap warm-up chain seen in the HAR.
CHATGPT_ANON_BOOTSTRAP_ENABLED = True
CHATGPT_AUTH_BOOTSTRAP_ENABLED = True
# True a warm-up failure aborts the main flow; the default is False, which only logs and continues.
CHATGPT_BOOTSTRAP_STRICT = False

# Retry settings for temporary network failures such as proxy connection, TLS, timeouts and connection resets in pure-protocol registration.
# Total attempts include the first request; backoff intervals are delay, delay*2,delay*4……
OPENAI_PROXY_RETRY_MAX_ATTEMPTS = 3
OPENAI_PROXY_RETRY_DELAY = 1.0
# The login page pre-check uses its own short timeout. A reachable proxy port does not mean its upstream TLS link works,
# so a dead node does not hold a registration worker for a long time under the global 30-second timeout.
OPENAI_PREFLIGHT_TIMEOUT = 12.0


apply_env_overrides(globals(), {
    "OPENAI_PROXY_RETRY_MAX_ATTEMPTS": "int",
    "OPENAI_PROXY_RETRY_DELAY": "float",
    "OPENAI_PREFLIGHT_TIMEOUT": "float",
})
