# -*- coding: utf-8 -*-
"""
Codex OAuth Standalone verification script (rewritten 2026-06-15: brand new session + SMS code receiving approach).

Purpose:
    Without registering again, take an **already registered email** and rerun Codex authorization on its own,
    running through "brand new clean session, email OTP, phone SMS verification (code receiving), pick workspace, get code, exchange token, save to disk".
    The first run is used to calibrate the response handling of each /api/accounts/* endpoint.

Usage:
    python tools/test_codex_oauth.py --email <registered-email> [--verbose]

Prerequisites:
    - The email has full credentials (client_id/refresh_token) in the email pool (用于注册的邮箱.json), used to receive the email OTP OTP
    - config/codex.py has ENABLE_CODEX_AUTO=True and the code-receiving settings (SMS_*) are filled in
    - Actually consumes: one email OTP for that email + one code-receiving SMS (about $0.13)

Output:
    - Full [Codex] / [SMS] logs throughout
    - On success, save to codex_accounts/codex-email.json and print PASS
    - On failure, print FAIL + the full stack trace, to locate which step it is stuck at
"""
import argparse
import logging
import sys
from pathlib import Path

# Let tools/ scripts import from the project root: core / config
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from core.codex_oauth import run_codex_oauth

logger = logging.getLogger("codex_test")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    # Make the DEBUG logs of the core module visible as well (to see details such as redirect following)
    logging.getLogger("core").setLevel(logging.DEBUG if verbose else logging.INFO)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Codex OAuth standalone verification (brand new session + SMS code receiving)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--email",
        required=True,
        help="Registered email (must have credentials in the email pool, used to receive the email OTP)",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        help="Proxy address (when not passed one is drawn from PROXY_POOL at random)",
    )
    parser.add_argument("--verbose", action="store_true", help="Show DEBUG logs (including redirect following details)")
    args = parser.parse_args()
    _setup_logging(args.verbose)

    logger.info("=" * 60)
    logger.info(f"[test] Rerunning Codex authorization on its own:{args.email}")
    logger.info("=" * 60)

    result = run_codex_oauth(args.email, proxy=args.proxy, force=True)

    logger.info("-" * 60)
    logger.info(f"[test] Result:status={result.get('status')}, ok={result.get('ok')}")
    if result.get("ok"):
        logger.info("=" * 60)
        logger.info("✅✅✅ [PASS] Codex OAuth verification passed ✅✅✅")
        logger.info(f"    Email     = {result.get('email')}")
        logger.info(f"    Saved file = {result.get('file_path')}")
        logger.info(f"    Callback URL  = {result.get('callback_url')}")
        logger.info(f"    Note     = {result.get('message')}")
        logger.info("=" * 60)
        return 0
    else:
        logger.error("=" * 60)
        logger.error(f"❌ [FAIL] Codex OAuth verification failed")
        logger.error(f"    status  = {result.get('status')}")
        logger.error(f"    message = {result.get('message')}")
        logger.error("=" * 60)
        logger.error("Tip: send the [Codex]/[SMS] logs above to the developer, to locate which step it is stuck at.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
