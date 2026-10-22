# -*- coding: utf-8 -*-
"""
Human-like operation pacing configuration.

The protocol requests themselves are very fast; a real browser used by a human normally has pauses for page loading, reading, typing, switching mailboxes
and so on. Lightweight random delays are configured here so the whole flow does not run on a fixed beat.
"""
from config.env_loader import apply_env_overrides

# Master switch. When off, delay() returns immediately.
ENABLE_HUMANIZE_DELAY = True

# Delay multiplier; reduce it to 0.5 when batch runs are too slow.
HUMANIZE_DELAY_FACTOR = 1.0

# Roxy/Cloak Randomization of browser automation actions. When enabled, clicks/typing closer to a human are used:
# - scroll slightly before clicking, move to a random position inside the element, pause briefly, then click
# - typing uses a random rhythm per character / small chunk instead of sending the whole string at once send_keys
# - a few random pauses / mouse movements after the page opens
ENABLE_HUMANIZE_BROWSER_ACTIONS = True

# Random pause ranges (seconds) for each kind of action.
HUMANIZE_DELAYS = {
    # Normal API interval: looks like page JS handling state after finishing a request.
    "api": (0.45, 1.35),
    # Wait for the page to settle after a page navigation / redirect.
    "navigate": (1.2, 3.2),
    # Sentinel / Turnstile / PoW related, leaving time for the SDK to run and the UI to wait.
    "challenge": (0.8, 2.4),
    # After the email verification code arrives, simulate the user switching back to the page and typing.
    "otp_input": (2.5, 8.0),
    # Filling in forms such as name and birthday.
    "form": (1.8, 5.0),
    # Entering the app and pulling the session after registration completes.
    "post_auth": (1.5, 4.0),
    # Staggering of concurrent tasks.
    "job_stagger": (0.4, 1.8),
    # Observe / move the mouse before clicking.
    "click": (0.15, 0.85),
    # Interval between single-character inputs.
    "keystroke": (0.035, 0.18),
    # Occasional pauses while typing.
    "typing_pause": (0.18, 0.75),
    # Short observation after a page opens.
    "page_warmup": (0.7, 2.2),
}

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'ENABLE_HUMANIZE_DELAY': 'bool', 'HUMANIZE_DELAY_FACTOR': 'float', 'ENABLE_HUMANIZE_BROWSER_ACTIONS': 'bool'})
