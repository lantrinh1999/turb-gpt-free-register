# -*- coding: utf-8 -*-
"""
Registration basics (defaults)

CLI main.py reads these first; the web console uses the same defaults for batch registration.
Empty fields trigger interactive input or auto-generation (the email is taken from the Outlook pool only when USE_EMAIL_SERVICE=True).
"""
from config.env_loader import apply_env_overrides

# Registration email (when empty and USE_EMAIL_SERVICE=True, taken from the Outlook pool)
REGISTER_EMAIL = ""

# Registration password (no longer needed by the OTP-only flow, kept as a fallback)
REGISTER_PASSWORD = ""

# Username (display name set after registration; when empty one is generated in the form "Foo Bar")
# OpenAI Restriction: name_invalid_chars - only letters and spaces are allowed
REGISTER_NAME = ""

# Whether to automatically check the plan / Plus eligibility after a successful registration is saved to the database.
# When disabled, backend-api/accounts/check is not called right after registration; it can be queried manually from the account list later.
AUTO_PLAN_CHECK_AFTER_REGISTER = False

# Pure-protocol registration fingerprint lifecycle:
#   False = Every registration job creates a fresh device/session/browser profile (default)
#   True  = Reuse a stable fingerprint when the same email registers again or is rerun; different emails stay independent
PROTOCOL_REUSE_FINGERPRINT_BY_EMAIL = False

# After registration succeeds and the accessToken is obtained, stay in the browser for a random time before closing the connection.
# Format: min seconds,max seconds. Set to "0,0" for no extra stay.
POST_REGISTER_DWELL_SECONDS_RANGE = "5,15"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'REGISTER_EMAIL': 'str',
    'REGISTER_NAME': 'str',
    'AUTO_PLAN_CHECK_AFTER_REGISTER': 'bool',
    'PROTOCOL_REUSE_FINGERPRINT_BY_EMAIL': 'bool',
    'POST_REGISTER_DWELL_SECONDS_RANGE': 'str',
})
