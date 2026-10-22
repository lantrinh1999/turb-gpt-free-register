# -*- coding: utf-8 -*-
"""
Settings for automatically triggering a Flow after a successful registration.
Set ENABLE_FLOW_TRIGGER = False to skip this step completely.
"""
from config.env_loader import apply_env_overrides

# Whether to enable the automatic Flow trigger (False = skip, does not affect the registration result)
ENABLE_FLOW_TRIGGER: bool = False

# Flow trigger endpoint address
FLOW_TRIGGER_URL: str = ""

# Bearer Token(Authorization header)
FLOW_TRIGGER_BEARER: str = ""

# Cookie string
FLOW_TRIGGER_COOKIE: str = ""

# JSON payload to send (access_token is injected into it)
FLOW_TRIGGER_PAYLOAD: dict = {}

# Request timeout (seconds)
FLOW_TRIGGER_TIMEOUT: int = 15

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'ENABLE_FLOW_TRIGGER': 'bool'})
