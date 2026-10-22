# -*- coding: utf-8 -*-
"""sub2api integration configuration."""
from config.env_loader import apply_env_overrides

# Whether to sync to sub2api automatically after a Codex Agent Token is generated successfully.
SUB2API_AUTO_EXPORT: bool = True

# Sync mode:
# api  = Upload directly by calling the sub2api API
# file = Only append/update the local sub2api.json
# both = An API upload success/failure does not affect the local file sync
SUB2API_SYNC_MODE: str = "api"

# sub2api API base URL; both Agent Token upload and Codex OAuth reuse this address.
SUB2API_API_BASE: str = ""

# Compatible with the old setting: Agent Token uploads directly to the full URL.
SUB2API_API_URL: str = ""

# sub2api management API Key; if empty no auth header is sent.
SUB2API_API_KEY: str = ""

# Compatible with the old setting name: SUB2API_API_TOKEN.
SUB2API_API_TOKEN: str = ""

# sub2api Management API auth header: x-api-key: <your-admin-api-key>.
SUB2API_API_AUTH_HEADER: str = "x-api-key"

# x-api-key No Bearer prefix is needed.
SUB2API_API_AUTH_PREFIX: str = ""

# Upload timeout in seconds.
SUB2API_API_TIMEOUT: int = 20

# Output path of the local sub2api config file; a relative path is resolved against the project root.
SUB2API_OUTPUT_PATH: str = "sub2api.json"

# Optional proxy key; written to account.proxy_key, and used to initialize proxies[0].proxy_key when proxies in sub2api.json is empty.
SUB2API_PROXY_KEY: str = ""


# ============================================================
# Codex OAuth authorization integration sub2
# Used when config.codex.CODEX_AUTH_URL_SOURCE="sub2":
#   1) Get the Codex authorization link from sub2
#   2) After the browser/protocol flow gets the localhost callback it is sent back to sub2
# ============================================================

# Compatible with the old setting: base URL of the sub2 Codex management API; when empty SUB2API_API_BASE is used.
SUB2_CODEX_API_BASE: str = ""

# Path of the endpoint that gets the Codex authorization link.
# sub2api current endpoint:POST /api/v1/admin/openai/generate-auth-url
SUB2_CODEX_AUTH_URL_PATH: str = "/api/v1/admin/openai/generate-auth-url"

# Path of the endpoint that uploads/submits the OAuth callback and creates the account.
# sub2api current create-account endpoint:POST /api/v1/admin/openai/create-from-oauth
SUB2_CODEX_CALLBACK_PATH: str = "/api/v1/admin/openai/create-from-oauth"

# Compatible with the old setting: auth token of the sub2 Codex API; when empty SUB2API_API_KEY / SUB2API_API_TOKEN is reused.
SUB2_CODEX_API_TOKEN: str = ""

# Auth header name/prefix; when empty SUB2API_API_AUTH_HEADER / SUB2API_API_AUTH_PREFIX is reused.
SUB2_CODEX_AUTH_HEADER: str = ""
SUB2_CODEX_AUTH_PREFIX: str = ""

# callback upload payload:
# create_from_oauth => sub2api Native account creation:{"session_id","code","state","redirect_uri","name","concurrency","priority"}
# exchange_code     => Only exchange the token, do not create the account (legacy behavior, kept for compatibility)
SUB2_CODEX_CALLBACK_PAYLOAD_MODE: str = "create_from_oauth"

apply_env_overrides(globals(), {
    'SUB2API_AUTO_EXPORT': 'bool',
    'SUB2API_SYNC_MODE': 'str',
    'SUB2API_API_BASE': 'str',
    'SUB2API_API_URL': 'str',
    'SUB2API_API_KEY': 'str',
    'SUB2API_API_TOKEN': 'str',
    'SUB2API_API_AUTH_HEADER': 'str',
    'SUB2API_API_AUTH_PREFIX': 'str',
    'SUB2API_API_TIMEOUT': 'int',
    'SUB2API_OUTPUT_PATH': 'str',
    'SUB2API_PROXY_KEY': 'str',
    'SUB2_CODEX_API_BASE': 'str',
    'SUB2_CODEX_AUTH_URL_PATH': 'str',
    'SUB2_CODEX_CALLBACK_PATH': 'str',
    'SUB2_CODEX_API_TOKEN': 'str',
    'SUB2_CODEX_AUTH_HEADER': 'str',
    'SUB2_CODEX_AUTH_PREFIX': 'str',
    'SUB2_CODEX_CALLBACK_PAYLOAD_MODE': 'str',
})
