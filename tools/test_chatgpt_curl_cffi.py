#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChatGPT backend-api fingerprint environment request test script.

Purpose:
    First create the unified BrowserSession fingerprint environment of the project (curl_cffi TLS fingerprint + UA/language/timezone profile + oai-did cookie),
    then use that environment to test Bearer token requests to the ChatGPT backend-api.

Usage:
    # Method 1: directly pass the token
    python3 tools/test_chatgpt_curl_cffi.py --token '<JWT>' --verbose

    # Method 2: read the token from a file (the first non-empty line by default; a Bearer prefix is allowed)
    python3 tools/test_chatgpt_curl_cffi.py --token-file 注册成功的token.txt

    # Method 3: test subscriptions, which requires passing account_id
    python3 tools/test_chatgpt_curl_cffi.py --token '<JWT>' --endpoint subscriptions --account-id '<account_id>'

    # Proxy: if not passed, the project pick_proxy() is used; pass an empty string to disable the proxy; pass a specific address to use that proxy
    python3 tools/test_chatgpt_curl_cffi.py --token '<JWT>' --proxy ''

Notes:
    - This script does not persist the token to disk.
    - Default endpoint=accounts-check.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote

# Let tools/ scripts import from the project root: core / config
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from core.session import BrowserSession  # noqa: E402

logger = logging.getLogger("chatgpt_curl_cffi_test")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("core").setLevel(logging.DEBUG if verbose else logging.INFO)


def _mask(s: str, left: int = 14, right: int = 8) -> str:
    if not s:
        return ""
    if len(s) <= left + right:
        return "***"
    return f"{s[:left]}...{s[-right:]}"


def _normalize_token(token: str) -> str:
    token = (token or "").strip().strip('"').strip("'")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _read_token_file(path: str, index: int = 0) -> str:
    p = Path(path).expanduser().resolve()
    lines = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Compatible with common formats: bare token / email----token / email:token / JSON line
        token = ""
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                token = obj.get("token") or obj.get("access_token") or obj.get("bearer") or ""
            except Exception:
                token = ""
        if not token:
            if "----" in line:
                token = line.rsplit("----", 1)[-1]
            elif "\t" in line:
                token = line.rsplit("\t", 1)[-1]
            else:
                token = line
        token = _normalize_token(token)
        if token:
            lines.append(token)
    if not lines:
        raise RuntimeError(f"token file has no usable content: {p}")
    if index < 0 or index >= len(lines):
        raise RuntimeError(f"--token-index out of range: {index}, number of usable tokens in the file={len(lines)}")
    return lines[index]


def _decode_jwt_payload_unverified(token: str) -> dict:
    """Only used to parse account_id/plan/email locally; the signature is not verified."""
    try:
        import base64

        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def _extract_account_id(token: str) -> Optional[str]:
    payload = _decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    return auth.get("chatgpt_account_id")


def _build_url(endpoint: str, token: str, account_id: Optional[str], timezone_offset_min: str) -> tuple[str, str, str]:
    if endpoint == "accounts-check":
        path = "/backend-api/accounts/check/v4-2023-04-27"
        url = f"https://chatgpt.com{path}?timezone_offset_min={quote(str(timezone_offset_min))}"
        return url, path, path
    if endpoint == "subscriptions":
        account_id = account_id or _extract_account_id(token)
        if not account_id:
            raise RuntimeError("endpoint=subscriptions requires --account-id, or the token payload to contain chatgpt_account_id")
        path = "/backend-api/subscriptions"
        url = f"https://chatgpt.com{path}?account_id={quote(account_id)}"
        return url, path, path
    raise RuntimeError(f"unknown endpoint: {endpoint}")


def _build_headers(env: BrowserSession, token: str, target_path: str, target_route: str) -> Dict[str, str]:
    headers = env._get_common_headers()  # Reuse the unified fingerprint profile headers of the project
    headers.update(
        {
            "accept": "*/*",
            "authorization": f"Bearer {token}",
            "oai-device-id": env.device_id,
            "oai-language": env.navigator_language(),
            "referer": "https://chatgpt.com/",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "x-openai-target-path": target_path,
            "x-openai-target-route": target_route,
        }
    )
    return headers


def _try_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _print_profile(env: BrowserSession) -> None:
    p = env.browser_profile or {}
    logger.info("[Fingerprint] proxy=%s", env.proxy if env.proxy else "<direct>")
    logger.info("[Fingerprint] device_id=%s", env.device_id)
    logger.info("[Fingerprint] ua=%s", p.get("user_agent"))
    logger.info("[Fingerprint] accept_language=%s", p.get("accept_language"))
    logger.info("[Fingerprint] navigator_language=%s", p.get("navigator_language"))
    logger.info("[Fingerprint] timezone=%s offset=%s", p.get("timezone_iana"), p.get("timezone_offset_minutes"))
    logger.info("[Fingerprint] screen=%sx%s dpr=%s", p.get("screen_width"), p.get("screen_height"), p.get("device_pixel_ratio"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ChatGPT backend-api curl_cffi fingerprint environment request test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--token", default=None, help="Bearer JWT; with or without the Bearer prefix")
    parser.add_argument("--token-file", default=None, help="Read the token from a file, default to the first non-empty line")
    parser.add_argument("--token-index", type=int, default=0, help="Which token to use when reading the token file, default 0")
    parser.add_argument(
        "--endpoint",
        choices=["accounts-check", "subscriptions"],
        default="accounts-check",
        help="Endpoint to test, default accounts-check",
    )
    parser.add_argument("--account-id", default=None, help="subscriptions Endpoint account_id; if not passed, try to extract it from the JWT payload")
    parser.add_argument("--timezone-offset-min", default="-", help="accounts-check parameter, default -")
    parser.add_argument("--proxy", default=None, help="Proxy; if not passed, a random one is picked from the project proxy pool; pass an empty string to disable the proxy")
    parser.add_argument("--verbose", action="store_true", help="Show DEBUG logs")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    token = _normalize_token(args.token or "")
    if not token and args.token_file:
        token = _read_token_file(args.token_file, args.token_index)
    if not token:
        logger.error("Missing token: pass --token or --token-file")
        return 2

    logger.info("=" * 70)
    logger.info("[test] Creating the BrowserSession fingerprint environment")
    logger.info("=" * 70)
    env = BrowserSession(proxy=args.proxy)
    _print_profile(env)

    payload = _decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    if payload:
        logger.info("[Token] sub=%s", payload.get("sub"))
        logger.info("[Token] email=%s", profile.get("email"))
        logger.info("[Token] account_id=%s", auth.get("chatgpt_account_id"))
        logger.info("[Token] plan=%s", auth.get("chatgpt_plan_type"))
        logger.info("[Token] exp=%s", payload.get("exp"))
    logger.info("[Token] masked=%s", _mask(token))

    try:
        url, target_path, target_route = _build_url(
            args.endpoint,
            token,
            args.account_id,
            args.timezone_offset_min,
        )
    except Exception as exc:
        logger.error("Failed to build URL:%s", exc)
        return 2

    headers = _build_headers(env, token, target_path, target_route)

    logger.info("-" * 70)
    logger.info("[Requesting] GET %s", url)
    if args.verbose:
        safe_headers = dict(headers)
        safe_headers["authorization"] = f"Bearer {_mask(token)}"
        logger.debug("[request headers] %s", json.dumps(safe_headers, ensure_ascii=False, indent=2))

    started = time.time()
    try:
        resp = env.session.get(url, headers=headers, allow_redirects=False)
    except Exception as exc:
        logger.exception("[request] Exception:%s: %s", type(exc).__name__, exc)
        return 1
    elapsed = time.time() - started

    logger.info("-" * 70)
    logger.info("[response] HTTP %s %s, elapsed %.2fs", resp.status_code, getattr(resp, "reason", ""), elapsed)
    logger.info("[response] content-type=%s", resp.headers.get("content-type"))

    if args.verbose:
        logger.debug("[response headers]")
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                v = "<redacted>"
            logger.debug("  %s: %s", k, v)

    print("-" * 70)
    text = resp.text or ""
    data = _try_json(text)
    if data is not None:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(text[:4000])
        if len(text) > 4000:
            print(f"\n... truncated, original length {len(text)} characters")

    if 200 <= resp.status_code < 300:
        logger.info("✅ [PASS] request succeeded")
        return 0
    logger.error("❌ [FAIL] Request failed status=%s", resp.status_code)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
