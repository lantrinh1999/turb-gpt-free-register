# -*- coding: utf-8 -*-
"""
Sentinel Token generation module
Reverse-engineered from the sdk.js of sentinel.openai.com sdk.js

Core logic:
1. Generate the `p` field (browser fingerprint data, a base64-encoded JSON array)
2. Send a POST request to sentinel.openai.com/backend-api/sentinel/req
3. Parse the token, turnstile and proofofwork
4. Compute the Proof of Work (FNV-1a hash)
5. Assemble the final openai-sentinel-token request header value
"""
import json
import time
import math
import random
import base64
import hashlib
from datetime import datetime, timezone, timedelta

from config import (
    USER_AGENT, SENTINEL_SV, NAVIGATOR_LANGUAGE, NAVIGATOR_LANGUAGES,
    TIMEZONE_OFFSET_MINUTES, TIMEZONE_NAME, SCREEN_WIDTH, SCREEN_HEIGHT,
    HARDWARE_CONCURRENCY, JS_HEAP_SIZE_LIMIT, NAVIGATOR_PROTO_SAMPLES,
    DOCUMENT_KEY_SAMPLES, WINDOW_KEY_SAMPLES, WINDOW_FEATURE_FLAGS,
)


def generate_fingerprint_data(device_id: str, attempt: int = 1, elapsed_ms: float = 0, profile: dict | None = None) -> str:
    """
    Generate the browser fingerprint data (the p field).
    Corresponds to the getConfig() + N() functions in the SDK.

    SDK The array structure returned by getConfig() in the SDK:
    [
        screen.width + screen.height,           # [0] sum of screen width and height
        "" + new Date,                           # [1] current time string
        performance.memory.jsHeapSizeLimit,      # [2] JS heap size limit
        Math.random() / attempt,                 # [3] random number (replaced by the attempt count in PoW)
        navigator.userAgent,                     # [4] UA
        a random script src,                          # [5] a random script tag's src
        data-build attribute value,                       # [6] data-build attribute of document.documentElement
        navigator.language,                      # [7] Language
        navigator.languages.join(","),            # [8] language list
        Math.random(),                           # [9] random number (replaced by the elapsed time in PoW)
        a random navigator property,                       # [10] a random navigator prototype method
        a random document key,                        # [11] a random document key
        a random window key,                          # [12] a random window key
        performance.now(),                       # [13] high-resolution time
        sid (UUID),                              # [14] session ID
        URL search params,                       # [15] URL query parameters
        navigator.hardwareConcurrency,           # [16] CPU core count
        performance.timeOrigin,                  # [17] performance time origin
        Number("ai" in window),                  # [18] window.ai whether it exists
        Number("InstallTrigger" in window),      # [19] Firefox specific → 0
        Number("cache" in window),               # [20] window.cache whether it exists
        Number("data" in window),                # [21] window.data whether it exists
        Number("solana" in window),              # [22] Solana wallet → 0
        Number("dump" in window),                # [23] Firefox specific → 0
        Number("requestIdleCallback" in window), # [24] whether it is supported requestIdleCallback
    ]

    Args:
        device_id: device ID
        attempt: PoW attempt count (used to replace [3])
        elapsed_ms: PoW elapsed milliseconds (used to replace [9])
    """
    profile = profile or {}
    screen_width = int(profile.get("screen_width", SCREEN_WIDTH))
    screen_height = int(profile.get("screen_height", SCREEN_HEIGHT))
    js_heap_size_limit = int(profile.get("js_heap_size_limit", JS_HEAP_SIZE_LIMIT))
    hardware_concurrency = int(profile.get("hardware_concurrency", HARDWARE_CONCURRENCY))
    navigator_language = str(profile.get("navigator_language", NAVIGATOR_LANGUAGE))
    navigator_languages = list(profile.get("navigator_languages", NAVIGATOR_LANGUAGES))
    user_agent = str(profile.get("user_agent", USER_AGENT))
    build_id = profile.get("build_id")
    react_listening_key = str(profile.get("react_listening_key") or ("_reactListening" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=11))))
    react_container_key = str(profile.get("react_container_key") or ("__reactContainer$" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=11))))
    react_resources_key = str(profile.get("react_resources_key") or react_container_key.replace("__reactContainer$", "__reactResources$", 1))
    tz_offset = int(profile.get("timezone_offset_minutes", TIMEZONE_OFFSET_MINUTES))
    tz_name = str(profile.get("timezone_name", TIMEZONE_NAME))

    # Simulate a Chrome browser environment; Date.toString stays consistent with the configured timezone.
    tz = timezone(timedelta(minutes=tz_offset))
    now = datetime.now(tz)
    sign = "+" if tz_offset >= 0 else "-"
    abs_minutes = abs(tz_offset)
    gmt = f"GMT{sign}{abs_minutes // 60:02d}{abs_minutes % 60:02d}"
    date_str = now.strftime(f"%a %b %d %Y %H:%M:%S {gmt} ({tz_name})")

    # Simulate performance.now() and performance.timeOrigin, keeping
    # timeOrigin + now ≈ Date.now(), so the times within the same p array do not contradict each other.
    perf_now = random.uniform(1000, 8000)
    time_origin = time.time() * 1000 - perf_now

    # Generate the sid (the session ID inside the SDK)
    sid = str(device_id)

    # Shares the same candidate keys with the JS VM environment of sentinel-runner.js;
    # SDK they are sampled randomly each time; the sampled values may change, but the candidate set must really exist.
    navigator_props = list(profile.get("navigator_proto_samples") or NAVIGATOR_PROTO_SAMPLES)
    document_keys = list(profile.get("document_key_samples") or DOCUMENT_KEY_SAMPLES)
    window_keys = list(profile.get("window_key_samples") or WINDOW_KEY_SAMPLES)
    window_flags = dict(WINDOW_FEATURE_FLAGS)
    window_flags.update(profile.get("window_feature_flags") or {})
    script_src_samples = list(profile.get("script_src_samples") or [f"https://sentinel.openai.com/sentinel/{SENTINEL_SV}/sdk.js"])

    config = [
        screen_width + screen_height,       # [0] screen.width + screen.height
        date_str,                        # [1] time string
        js_heap_size_limit,              # [2] jsHeapSizeLimit
        attempt,                         # [3] PoW attempt count / Math.random()
        user_agent,                      # [4] UA
        random.choice(script_src_samples),  # [5] script src
        build_id,                        # [6] data-build
        navigator_language,              # [7] navigator.language
        ",".join(navigator_languages),   # [8] navigator.languages
        round(elapsed_ms) if elapsed_ms else random.randint(1, 100),  # [9] elapsed time / Math.random()
        random.choice(navigator_props),  # [10] a random navigator property
        random.choice(document_keys + [react_listening_key, react_container_key, react_resources_key]),  # [11] a random document key / React injected key
        random.choice(window_keys),       # [12] random window key
        round(perf_now, 10),             # [13] performance.now()
        sid,                             # [14] sid
        "",                              # [15] URL search params (usually empty on the registration page)
        hardware_concurrency,            # [16] hardwareConcurrency
        round(time_origin, 1),           # [17] performance.timeOrigin
        int(window_flags.get("ai", 0)),                 # [18] Number("ai" in window)
        int(window_flags.get("InstallTrigger", 0)),     # [19] Firefox specific
        int(window_flags.get("cache", 0)),              # [20] Number("cache" in window)
        int(window_flags.get("data", 0)),               # [21] Number("data" in window)
        int(window_flags.get("solana", 0)),             # [22] wallet extension
        int(window_flags.get("dump", 0)),               # [23] Firefox specific
        int(window_flags.get("requestIdleCallback", 0)), # [24] Safari not exposed by default requestIdleCallback
    ]
    return config


def encode_config(config: list) -> str:
    """
    Encode the config array into a base64 string.
    Corresponds to the N() function in the SDK:
        JSON.stringify(t) → TextEncoder.encode() → btoa(String.fromCharCode(...))

    Note: the SDK uses TextEncoder to encode the JSON string into UTF-8 bytes, then applies btoa byte by byte.
    This is equivalent to the Python:json_str.encode('utf-8') → base64 encode
    """
    json_str = json.dumps(config, ensure_ascii=False, separators=(',', ':'))
    # Encode with UTF-8 and then base64 (consistent with TextEncoder + btoa of the SDK)
    encoded = base64.b64encode(json_str.encode('utf-8')).decode('ascii')
    return encoded


def fnv1a_hash(text: str) -> str:
    """
    FNV-1a hash algorithm (32-bit).
    Corresponds to the hash function in the SDK, used for the Proof of Work check.

    JS Original code:
        let e = 2166136261;
        for (let r = 0; r < t.length; r++)
            e ^= t.charCodeAt(r),
            e = Math.imul(e, 16777619) >>> 0;
        e ^= e >>> 16;
        e = Math.imul(e, 2246822507) >>> 0;
        e ^= e >>> 13;
        e = Math.imul(e, 3266489909) >>> 0;
        e ^= e >>> 16;
        return (e >>> 0).toString(16).padStart(8, "0");
    """
    h = 2166136261
    for ch in text:
        h ^= ord(ch)
        # Math.imul Simulation: 32-bit integer multiplication
        h = _imul(h, 16777619) & 0xFFFFFFFF

    h ^= (h >> 16)
    h = _imul(h, 2246822507) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = _imul(h, 3266489909) & 0xFFFFFFFF
    h ^= (h >> 16)
    h = h & 0xFFFFFFFF

    return format(h, '08x')


def _imul(a: int, b: int) -> int:
    """
    Simulate Math.imul of JavaScript (32-bit integer multiplication).
    Python integers do not overflow, so they must be truncated to 32 bits manually.
    """
    # Make sure it is a 32-bit unsigned integer
    a = a & 0xFFFFFFFF
    b = b & 0xFFFFFFFF
    # 32-bit integer multiplication
    result = (a * b) & 0xFFFFFFFF
    return result


def solve_proof_of_work(seed: str, difficulty: str, device_id: str, max_attempts: int = 500000, profile: dict | None = None) -> str:
    """
    Compute the Proof of Work.

    SDK The logic of _runCheck in the SDK:
    1. Set config[3] to the attempt count (nonce)
    2. Set config[9] to Math.round(performance.now() - startTime)
    3. Encode config -> base64 string c
    4. Compute fnv1a(seed + c) -> 8-digit hex
    5. Return if hex[:len(difficulty)] <= difficulty, then c + "~S"

    Args:
        seed: The seed returned by the server seed
        difficulty: The difficulty returned by the server (hex prefix)
        device_id: device ID
        max_attempts: Maximum number of attempts

    Returns:
        PoW Answer string, in the format base64_encoded_config + "~S"
    """
    start_time = time.time() * 1000  # milliseconds

    # Generate the initial config
    config = generate_fingerprint_data(device_id, attempt=0, elapsed_ms=0, profile=profile)

    diff_len = len(difficulty)

    for i in range(max_attempts):
        # Update the attempt count and elapsed time
        config[3] = i
        config[9] = round(time.time() * 1000 - start_time)

        # Encode as base64
        encoded = encode_config(config)

        # Compute the hash
        hash_input = seed + encoded
        hash_result = fnv1a_hash(hash_input)

        # Check whether the difficulty requirement is met
        if hash_result[:diff_len] <= difficulty:
            return encoded + "~S"

    # If the maximum number of attempts is reached without finding one, return the error prefix
    return "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + encode_config(["e"])


def generate_requirements_token(device_id: str, profile: dict | None = None) -> str:
    """
    Generate the requirements token (the value of the p field).
    Corresponds to getRequirementsToken() in the SDK / getRequirementsToken() / _generateRequirementsTokenAnswerBlocking()

    This is the value of the p field the first time sentinel/req is called.
    It is simply the config encoding + the "~S" suffix, no PoW needed.
    """
    config = generate_fingerprint_data(device_id, attempt=1, elapsed_ms=0, profile=profile)
    encoded = encode_config(config)
    return "gAAAAAC" + encoded + "~S"


def build_sentinel_request_body(p: str, device_id: str, flow: str) -> str:
    """
    Build the request body of sentinel/req.

    Args:
        p: Fingerprint data (requirements token)
        device_id: device ID
        flow: flow type
            - "username_password_create": Step 6 (before registration)
            - "authorize_continue": Step 9 (after verification code validation)
            - "oauth_create_account": Step 11 (before creating the account)
    """
    body = {
        "p": p,
        "id": device_id,
        "flow": flow,
    }
    return json.dumps(body, separators=(',', ':'))


def build_sentinel_token_header(
    p: str,
    turnstile_token: str,
    sentinel_token: str,
    device_id: str,
    flow: str
) -> str:
    """
    Build the value of the openai-sentinel-token request header.

    The final format is a JSON string:
    {"p":"<proof>","t":"<turnstile>","c":"<token>","id":"<device_id>","flow":"<flow>"}
    """
    header_value = {
        "p": p,
        "t": turnstile_token or "",
        "c": sentinel_token,
        "id": device_id,
        "flow": flow,
    }
    return json.dumps(header_value, separators=(',', ':'))


def get_enforcement_token(sentinel_response: dict, seed: str, difficulty: str, device_id: str, profile: dict | None = None) -> str:
    """
    When there is a PoW requirement, compute the enforcement token (the p field with PoW).
    Corresponds to getEnforcementToken() in the SDK.

    Args:
        sentinel_response: sentinel/req response JSON
        seed: proofofwork.seed
        difficulty: proofofwork.difficulty
        device_id: device ID

    Returns:
        PoW Result string (base64 + ~S)
    """
    pow_data = sentinel_response.get("proofofwork", {})

    if pow_data.get("required"):
        pow_seed = pow_data.get("seed", "")
        pow_difficulty = pow_data.get("difficulty", "")
        answer = solve_proof_of_work(pow_seed, pow_difficulty, device_id, profile=profile)
        return "gAAAAAB" + answer

    # When no PoW is needed, return the simple fingerprint
    return generate_requirements_token(device_id, profile=profile)
