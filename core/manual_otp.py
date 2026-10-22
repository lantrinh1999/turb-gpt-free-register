# -*- coding: utf-8 -*-
"""Manual OTP channel for non-interactive environments (for WebUI / background tasks).

Usage:
  1. The registration task calls wait_for_manual_otp(email)
  2. The user submits a 6-digit verification code for the task in the WebUI, or calls submit_manual_otp(email, code)
  3. The waiting side continues after getting the verification code
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict

logger = logging.getLogger(__name__)

_lock = threading.Lock()
# email(lower) -> list[code]  supports multiple verification codes for the same email
_codes: dict[str, list[str]] = defaultdict(list)
# email(lower) -> Event
_events: dict[str, threading.Event] = {}
# email(lower) -> waiting meta
_waiting: dict[str, dict] = {}


def _norm(email: str) -> str:
    return str(email or "").strip().lower()


def _event_for(email: str) -> threading.Event:
    key = _norm(email)
    ev = _events.get(key)
    if ev is None:
        ev = threading.Event()
        _events[key] = ev
    return ev


def mark_waiting(email: str, job_id: int | None = None) -> None:
    key = _norm(email)
    with _lock:
        _waiting[key] = {
            "email": email,
            "job_id": job_id,
            "since": time.time(),
        }
        _event_for(key).clear()


def clear_waiting(email: str) -> None:
    key = _norm(email)
    with _lock:
        _waiting.pop(key, None)


def list_waiting() -> list[dict]:
    with _lock:
        return [dict(v) for v in _waiting.values()]


def submit_manual_otp(email: str, code: str) -> dict:
    key = _norm(email)
    code = str(code or "").strip().replace(" ", "")
    if not key:
        raise ValueError("email is empty")
    if not code:
        raise ValueError("Verification code is empty")
    if not code.isdigit() or len(code) not in (4, 5, 6, 7, 8):
        # OpenAI usually 6 digits; slightly relaxed for compatibility
        raise ValueError(f"Verification code format looks wrong: {code!r}")
    with _lock:
        _codes[key].append(code)
        _event_for(key).set()
    logger.info("[ManualOTP] Verification code submitted:email=%s code=%s", email, code)
    return {"ok": True, "email": email, "code": code}


def pop_manual_otp(email: str) -> str | None:
    key = _norm(email)
    with _lock:
        queue = _codes.get(key) or []
        if not queue:
            return None
        code = queue.pop(0)
        if not queue:
            _event_for(key).clear()
        return code


def wait_for_manual_otp(email: str, *, timeout: int = 180, job_id: int | None = None) -> str:
    """Block while waiting for a manual verification code. Prefer an already submitted code, otherwise poll / wait for an event."""
    key = _norm(email)
    if not key:
        raise RuntimeError("Manual OTP: email is empty")

    # If a pre-submitted verification code exists, use it directly
    existing = pop_manual_otp(email)
    if existing:
        clear_waiting(email)
        return existing

    mark_waiting(email, job_id=job_id)
    logger.info(
        "[ManualOTP] Waiting for manual verification code input:email=%s timeout=%ss job=%s",
        email,
        timeout,
        job_id or "-",
    )
    logger.info("[ManualOTP] Please open email %s and submit the 6-digit verification code next to the task in the WebUI", email)

    # CLI Interactive fallback: if there is a TTY, terminal input is also allowed
    try:
        import sys
        has_tty = bool(getattr(sys, "stdin", None) and sys.stdin.isatty())
    except Exception:
        has_tty = False

    end = time.time() + max(10, int(timeout))
    ev = _event_for(key)
    try:
        while time.time() < end:
            code = pop_manual_otp(email)
            if code:
                return code

            if has_tty:
                # Non-blocking feel: wait briefly for an event, then prompt once more
                if ev.wait(timeout=1.0):
                    code = pop_manual_otp(email)
                    if code:
                        return code
                # Give the CLI a chance
                try:
                    typed = input(f">>> Manually enter the email verification code for {email}: ").strip()
                except EOFError:
                    typed = ""
                if typed:
                    submit_manual_otp(email, typed)
                    code = pop_manual_otp(email)
                    if code:
                        return code
            else:
                ev.wait(timeout=1.0)

            # Support the task being stopped manually
            try:
                from core.registration_service import check_stop_requested
                check_stop_requested()
            except Exception:
                pass
        raise TimeoutError(f"Timed out waiting for manual verification code ({timeout}s):{email}")
    finally:
        clear_waiting(email)
