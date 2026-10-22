# -*- coding: utf-8 -*-
"""
2FA(TOTP) configuration

Whether to set up 2FA automatically after a successful registration:
    True:  Registration completes -> fetch a new OTP email -> enroll TOTP -> activate -> write the secret into DB
    False: Skip the whole 2FA flow and only save the email + accessToken

Turning 2FA off does not affect account usability; it only means the account has no one-time-password protection and one OTP email fewer is received.
"""
from config.env_loader import apply_env_overrides

ENABLE_2FA = False

# 2FA network proxy mode:
#   saved = Prefer the valid proxy saved with the account (fall back to the proxy pool when there is none)
#   pool  = Ignore the proxy saved with the account and pick one from PROXY_POOL at random for every task
TWOFA_PROXY_MODE = "saved"

# Retries for temporary network errors when starting reauth (CSRF + signin). A 403 first clears the current session
# local circuit breaker and then retries with exponential backoff; business-level 4xx are not retried.
# OTP Submission also reuses this count/backoff configuration; only 403/429 without a business error code and without an interactive challenge are retried.
# OTP Retries reuse the same session/verification code; explicit account rejections, challenges and network timeouts with unknown outcome are not replayed automatically.
TWOFA_REAUTH_MAX_ATTEMPTS = 3
TWOFA_REAUTH_RETRY_DELAY = 3.0

# 2FA Background queue. workers is the number of accounts actually processed at the same time; restart the process after changing it to rebuild the thread pool.
TWOFA_WORKERS = 4
TWOFA_QUEUE_LIMIT = 200

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'ENABLE_2FA': 'bool',
    'TWOFA_PROXY_MODE': 'str',
    'TWOFA_REAUTH_MAX_ATTEMPTS': 'int',
    'TWOFA_REAUTH_RETRY_DELAY': 'float',
    'TWOFA_WORKERS': 'int',
    'TWOFA_QUEUE_LIMIT': 'int',
})
