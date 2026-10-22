# -*- coding: utf-8 -*-
"""
Sentinel Runner adapter layer
Invoke the project-root sentinel-runner.js via subprocess,
so that Node.js really runs sdk.js inside a vm sandbox and generates a sentinel-token that can pass validation.

How it works:
1. Python side first calls sentinel.openai.com/backend-api/sentinel/req to obtain the challenge JSON
2. Write the challenge to a temp file
3. Call node sentinel-runner.js --challenge-file <temp file> ...
4. Capture stdout, which is the openai-sentinel-token value
"""
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from config import (
    USER_AGENT,
    CHROME_MAJOR,
    CHROME_FULL_VERSION,
    SEC_CH_UA,
    SEC_CH_UA_PLATFORM,
    SEC_CH_UA_FULL_VERSION_LIST,
    SEC_CH_UA_PLATFORM_VERSION,
    SEC_CH_UA_ARCH,
    SEC_CH_UA_BITNESS,
    SEC_CH_UA_MODEL,
    TIMEZONE_IANA,
    TIMEZONE_NAME,
    TIMEZONE_OFFSET_MINUTES,
    NAVIGATOR_LANGUAGE,
    NAVIGATOR_LANGUAGES,
    SCREEN_WIDTH,
    SCREEN_HEIGHT,
    HARDWARE_CONCURRENCY,
    JS_HEAP_SIZE_LIMIT,
    DEVICE_MEMORY,
    SENTINEL_SV,
    OPENAI_BUILD_ID,
)

logger = logging.getLogger(__name__)

# Project root directory (parent of core)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Node resources live in the sentinel/ subdirectory of the project root
_SENTINEL_DIR = _PROJECT_ROOT / "sentinel"
_RUNNER_PATH = _SENTINEL_DIR / "sentinel-runner.js"
_SDK_PATH = _SENTINEL_DIR / "sdk.js"

# page-url for each flow (consistent with the actual browser page, affects sdk.js fingerprint generation)
_FLOW_PAGE_URL = {
    "username_password_create": "https://auth.openai.com/create-account/password",
    "email_otp_validate": "https://auth.openai.com/email-verification",
    "authorize_continue": "https://auth.openai.com/email-verification",
    "oauth_create_account": "https://auth.openai.com/about-you",
}

# Node Subprocess timeout (seconds). sdk.js may run PoW internally, so leave plenty of margin
_RUNNER_TIMEOUT = 60


def _resolve_node_executable() -> str:
    """
    Resolve the Node executable name. Defaults to node.exe on Windows, node on Unix-like systems.
    Can be overridden through the NODE_EXECUTABLE environment variable.
    """
    override = os.environ.get("NODE_EXECUTABLE")
    if override:
        return override
    return "node.exe" if sys.platform.startswith("win") else "node"


def _ensure_runner_environment() -> None:
    """Mandatory pre-launch check: runner.js / sdk.js must exist."""
    if not _RUNNER_PATH.exists():
        raise FileNotFoundError(f"Cannot find sentinel-runner.js: {_RUNNER_PATH}")
    if not _SDK_PATH.exists():
        raise FileNotFoundError(f"Cannot find sdk.js: {_SDK_PATH}")


def generate_sentinel_token(
    challenge: dict,
    flow: str,
    device_id: str,
    user_agent: str | None = None,
    page_url: str | None = None,
    browser_profile: dict | None = None,
    sentinel_sid: str | None = None,
    react_listening_key: str | None = None,
    react_container_key: str | None = None,
    react_resources_key: str | None = None,
    cookie: str | None = None,
) -> str:
    """
    Feed the challenge returned by sentinel.openai.com to sdk.js to generate the final sentinel-token string.

    Args:
        challenge: sentinel/req full JSON returned (including token / proofofwork / turnstile / so fields)
        flow: Flow identifier, e.g. username_password_create / authorize_continue / oauth_create_account
        device_id: oai-did, must be the same value held by the Python-side BrowserSession
        user_agent: Must match the Python-side request UA exactly; defaults to reading config.USER_AGENT
        page_url: URL of the current page (affects the referer / location fingerprint); inferred from flow by default

    Returns:
        openai-sentinel-token header full string value (runner stdout returned as is, already a JSON string)

    Raises:
        FileNotFoundError: runner.js or sdk.js is missing
        RuntimeError: Node subprocess error or non-zero exit code
    """
    _ensure_runner_environment()

    if not flow:
        raise ValueError("flow cannot be empty")
    if not device_id:
        raise ValueError("device_id cannot be empty")

    profile = browser_profile or {}
    browser_family = str(profile.get("browser_family") or "chrome")
    request_idle_callback = int((profile.get("window_feature_flags") or {}).get("requestIdleCallback", 0))
    ua = user_agent or str(profile.get("user_agent") or USER_AGENT)
    screen_width = int(profile.get("screen_width", SCREEN_WIDTH))
    screen_height = int(profile.get("screen_height", SCREEN_HEIGHT))
    hardware_concurrency = int(profile.get("hardware_concurrency", HARDWARE_CONCURRENCY))
    js_heap_size_limit = int(profile.get("js_heap_size_limit", JS_HEAP_SIZE_LIMIT))
    device_memory = int(profile.get("device_memory", DEVICE_MEMORY))
    device_pixel_ratio = float(profile.get("device_pixel_ratio", 2))
    screen_avail_width = int(profile.get("screen_avail_width", screen_width))
    screen_avail_height = int(profile.get("screen_avail_height", max(0, screen_height - 25)))
    outer_width = int(profile.get("outer_width", screen_avail_width))
    outer_height = int(profile.get("outer_height", screen_avail_height))
    inner_width = int(profile.get("inner_width", profile.get("viewport_width", outer_width)))
    inner_height = int(profile.get(
        "inner_height", profile.get("viewport_height", max(0, outer_height - 87))
    ))
    color_depth = int(profile.get("color_depth", 24))
    navigator_language = str(profile.get("navigator_language", NAVIGATOR_LANGUAGE))
    navigator_languages = list(profile.get("navigator_languages", NAVIGATOR_LANGUAGES))
    chrome_major = str(profile.get("chrome_major", CHROME_MAJOR))
    chrome_full_version = str(profile.get("chrome_full_version", CHROME_FULL_VERSION))
    sec_ch_ua = str(profile.get("sec_ch_ua", SEC_CH_UA))
    sec_ch_ua_platform = str(profile.get("sec_ch_ua_platform", SEC_CH_UA_PLATFORM))
    navigator_platform = str(profile.get("navigator_platform", "MacIntel"))
    navigator_vendor = str(profile.get("navigator_vendor", "Google Inc."))
    user_agent_data_platform = str(profile.get("user_agent_data_platform", sec_ch_ua_platform.strip('\"') or "macOS"))
    sec_ch_ua_full_version_list = str(profile.get("sec_ch_ua_full_version_list", SEC_CH_UA_FULL_VERSION_LIST))
    sec_ch_ua_platform_version = str(profile.get("sec_ch_ua_platform_version", SEC_CH_UA_PLATFORM_VERSION))
    sec_ch_ua_arch = str(profile.get("sec_ch_ua_arch", SEC_CH_UA_ARCH))
    sec_ch_ua_bitness = str(profile.get("sec_ch_ua_bitness", SEC_CH_UA_BITNESS))
    sec_ch_ua_model = str(profile.get("sec_ch_ua_model", SEC_CH_UA_MODEL))
    build_id = str(profile.get("build_id", OPENAI_BUILD_ID))
    # Auth page Sentinel token documentElement usually has no data-build;
    # ChatGPT page prepare/finalize p is what carries the front-end build.
    runner_build_id = "" if page_url is None and flow in {
        "email_otp_validate", "authorize_continue", "oauth_create_account", "username_password_create"
    } else build_id
    timezone_iana = str(profile.get("timezone_iana", TIMEZONE_IANA))
    timezone_name = str(profile.get("timezone_name", TIMEZONE_NAME))
    timezone_offset_minutes = int(profile.get("timezone_offset_minutes", TIMEZONE_OFFSET_MINUTES))
    runner_cookie = cookie or f"oai-did={device_id}"

    page = page_url or _FLOW_PAGE_URL.get(
        flow, "https://auth.openai.com/create-account/password"
    )

    # dx is obfuscated with the p used when sentinel/req was initiated. This proof is only passed to the runner locally,
    # and should not be exposed to the SDK as an extra field of the challenge.
    challenge_proof = str(challenge.get("_request_p") or "") if isinstance(challenge, dict) else ""
    challenge_payload = (
        {k: v for k, v in challenge.items() if k != "_request_p"}
        if isinstance(challenge, dict) else challenge
    )

    # Write the challenge to a temp file, to avoid command-line length / escaping problems
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix=f"sentinel-challenge-{flow}-",
        delete=False,
        encoding="utf-8",
    )
    try:
        json.dump(challenge_payload, tmp, ensure_ascii=False)
        tmp.flush()
        tmp.close()

        cmd = [
            _resolve_node_executable(),
            str(_RUNNER_PATH),
            "--challenge-file", tmp.name,
            "--flow", flow,
            "--device-id", device_id,
            "--sentinel-sid", sentinel_sid or "",
            "--challenge-proof", challenge_proof,
            "--react-listening-key", react_listening_key or "",
            "--react-container-key", react_container_key or str(profile.get("react_container_key") or ""),
            "--react-resources-key", react_resources_key or str(profile.get("react_resources_key") or ""),
            "--page-url", page,
            "--user-agent", ua,
            "--browser-family", browser_family,
            "--navigator-platform", navigator_platform,
            "--navigator-vendor", navigator_vendor,
            "--user-agent-data-platform", user_agent_data_platform,
            "--request-idle-callback", "1" if request_idle_callback else "0",
            "--sdk", str(_SDK_PATH),
            # challenge request initial p[5] all come from the versioned SDK; the final submitted header is generated by the
            # Auth page wrapper SDK: backend-api for password/profile pages, a versioned address for the OTP page.
            "--script-src", (
                f"https://sentinel.openai.com/sentinel/{SENTINEL_SV}/sdk.js"
                if flow == "email_otp_validate"
                else "https://sentinel.openai.com/backend-api/sentinel/sdk.js"
            ),
            "--build-id", runner_build_id,
            # Keep consistent with the fingerprint defaults in config.browser / core.sentinel.py
            "--width", str(screen_width),
            "--height", str(screen_height),
            "--avail-width", str(screen_avail_width),
            "--avail-height", str(screen_avail_height),
            "--outer-width", str(outer_width),
            "--outer-height", str(outer_height),
            "--inner-width", str(inner_width),
            "--inner-height", str(inner_height),
            "--color-depth", str(color_depth),
            "--cores", str(hardware_concurrency),
            "--language", navigator_language,
            "--languages", ",".join(navigator_languages),
            "--time-zone", timezone_iana,
            "--timezone-name", timezone_name,
            "--timezone-offset-minutes", str(timezone_offset_minutes),
            "--js-heap-size-limit", str(js_heap_size_limit),
            "--device-memory", str(device_memory),
            "--device-pixel-ratio", str(device_pixel_ratio),
            "--chrome-major", chrome_major,
            "--chrome-full-version", chrome_full_version,
            "--sec-ch-ua", sec_ch_ua,
            "--sec-ch-ua-platform", sec_ch_ua_platform,
            "--sec-ch-ua-full-version-list", sec_ch_ua_full_version_list,
            "--sec-ch-ua-platform-version", sec_ch_ua_platform_version,
            "--sec-ch-ua-arch", sec_ch_ua_arch,
            "--sec-ch-ua-bitness", sec_ch_ua_bitness,
            "--sec-ch-ua-model", sec_ch_ua_model,
            "--webgl-vendor", str(profile.get("webgl_vendor") or ""),
            "--webgl-renderer", str(profile.get("webgl_renderer") or ""),
            "--cookie", runner_cookie,
        ]

        logger.info(f"[SentinelRunner] Calling Node to generate token, flow={flow}")
        logger.debug(f"[SentinelRunner] Command: {' '.join(cmd)}")

        # Key point: disable automatic discovery of sentinel.config.json (avoid interference from external config)
        env = os.environ.copy()
        env.pop("SENTINEL_CONFIG", None)
        env["SENTINEL_CONFIG"] = "__none__"  # Deliberately point to a non-existent file, to skip the fallback list
        env["TZ"] = timezone_iana  # Make Date.toString() inside the Node VM consistent with the timezone of the Python p fingerprint

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                cwd=str(_PROJECT_ROOT),
                timeout=_RUNNER_TIMEOUT,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"sentinel-runner.js execution timed out (>{_RUNNER_TIMEOUT}s),flow={flow}"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Node executable not found, please make sure Node.js is installed and added to PATH,"
                "or specify the absolute path via the NODE_EXECUTABLE environment variable."
            ) from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            raise RuntimeError(
                f"sentinel-runner.js exit code {proc.returncode}\n"
                f"stderr: {stderr}\n"
                f"stdout: {stdout}"
            )

        token_text = (proc.stdout or "").strip()
        if not token_text:
            raise RuntimeError(
                f"sentinel-runner.js output is empty, stderr: {(proc.stderr or '').strip()}"
            )

        # Simple validity check: must be valid JSON and contain the key fields
        try:
            parsed = json.loads(token_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"runner output is not valid JSON: {token_text[:200]}"
            ) from exc

        for required_key in ("p", "c", "id", "flow"):
            if required_key not in parsed:
                raise RuntimeError(
                    f"runner output is missing field {required_key}: {token_text[:200]}"
                )

        # Detailed diagnostics: print all top-level field names of the output JSON + value lengths
        field_summary = {
            k: (len(v) if isinstance(v, str) else type(v).__name__)
            for k, v in parsed.items()
        }
        logger.info(
            f"[SentinelRunner] token generation succeeded, flow={flow}, "
            f"contains turnstile={'t' in parsed and bool(parsed.get('t'))}, "
            f"contains so={bool(parsed.get('_so') or parsed.get('so'))}, "
            f"field: {field_summary}"
        )
        return token_text

    finally:
        # Clean up temp files
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
