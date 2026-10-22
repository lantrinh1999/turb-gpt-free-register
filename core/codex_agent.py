"""
Codex Agent Identity auto-registration script
by Jiuwu

Flow:
1. Get account info via the ChatGPT session JWT
2. Generate an Ed25519 key pair
3. Register on auth.openai.com as an agent
4. Generate a Codex CLI-compatible auth.json

Dependencies:curl_cffi, cryptography
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import random
import string
import sys
import time
import uuid
from typing import Any

from curl_cffi import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
)


# ============================================================
#  Constants
# ============================================================

AUTHAPI_BASE = "https://auth.openai.com/api/accounts"
CHATGPT_BASE = "https://chatgpt.com"
IMPERSONATE = "chrome"

CHROME_VERSION = "146"
USER_AGENT = (
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    f"AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_VERSION}.0.0.0 Safari/537.36"
)

# Codex CLI agent version info
AGENT_VERSION = "0.138.0-alpha.6"
AGENT_HARNESS_ID = "codex-cli"
RUNNING_LOCATION = "local"


# ============================================================
#  log
# ============================================================

logger = logging.getLogger(__name__)


def _log(step: str, msg: str, level: str = "INFO") -> None:
    """Use logging uniformly, to avoid ANSI-colored stdout leaking into WebUI/task logs."""
    text = f"[CodexAgent][{step}] {msg}"
    if level in {"WARN", "WARNING"}:
        logger.warning(text)
    elif level == "ERROR":
        logger.error(text)
    else:
        logger.info(text)


def _banner(title: str) -> None:
    logger.info("[CodexAgent] %s", title)


def _fingerprint(value: str, length: int = 12) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:length]


# ============================================================
#  Ed25519 key pair generation
# ============================================================

def generate_ed25519_keypair() -> tuple[str, str]:
    """
    Generate an Ed25519 key pair.

    :return: (private_key_pkcs8_base64, public_key_ssh)
    """
    private_key = Ed25519PrivateKey.generate()

    # PKCS8 DER format private key → base64
    pkcs8_der = private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    private_key_b64 = base64.b64encode(pkcs8_der).decode()

    # Raw public key bytes
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # Build the SSH public key format: ssh-ed25519 base64(blob)
    ssh_header = b"ssh-ed25519"
    blob = bytearray()
    blob.extend(len(ssh_header).to_bytes(4, "big"))
    blob.extend(ssh_header)
    blob.extend(len(pub_bytes).to_bytes(4, "big"))
    blob.extend(pub_bytes)
    ssh_b64 = base64.b64encode(bytes(blob)).decode()
    public_key_ssh = f"ssh-ed25519 {ssh_b64}"

    return private_key_b64, public_key_ssh


# ============================================================
#  JWT decoding (signature not verified, only extracts claims)
# ============================================================

def decode_jwt_claims(jwt_token: str) -> dict[str, Any]:
    """
    Decode the JWT payload (signature not verified).

    :param jwt_token: JWT string
    :return: claims dict
    """
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    # JWT payload is base64url encoded
    payload_b64 = parts[1]
    # Add padding
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding

    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)


# ============================================================
#  Session retrieval
# ============================================================

def get_session_from_cookies(cookies: dict[str, str]) -> dict[str, Any]:
    """
    Call /api/auth/session with cookies to get the accessToken and account info.

    :param cookies: chatgpt.com session cookies dict
    :return: session data
    """
    r = requests.get(
        f"{CHATGPT_BASE}/api/auth/session",
        cookies=cookies,
        headers={"user-agent": USER_AGENT},
        impersonate=IMPERSONATE,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def get_session_from_access_token(access_token: str) -> dict[str, Any]:
    """
    If a JWT access token is already available, decode it directly to get the info.

    :param access_token: ChatGPT session JWT
    :return: Containing accessToken, accountId, email, userId, planType dict
    """
    claims = decode_jwt_claims(access_token)
    auth_info = claims.get("https://api.openai.com/auth", {})
    profile = claims.get("https://api.openai.com/profile", {})

    return {
        "accessToken": access_token,
        "accountId": auth_info.get("chatgpt_account_id", ""),
        "userId": auth_info.get("chatgpt_user_id", ""),
        "email": profile.get("email", ""),
        "planType": auth_info.get("chatgpt_plan_type", "free"),
    }


def _agent_headers(access_token: str, env: Any | None = None) -> dict[str, str]:
    """Build the Agent API request headers; when a BrowserSession is present, use that account independent fingerprint profile."""
    if env is not None and hasattr(env, "_get_common_headers"):
        headers = env._get_common_headers()
    else:
        headers = {"User-Agent": USER_AGENT}
    headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
    })
    if env is not None:
        try:
            headers["oai-device-id"] = env.device_id
            headers["oai-language"] = env.navigator_language()
            if hasattr(env, "_attach_auth_rum_headers"):
                env._attach_auth_rum_headers(headers)
        except Exception:
            pass
    return headers


def _agent_post(url: str, *, access_token: str, payload: dict[str, Any], env: Any | None = None, timeout: int = 15):
    """Send the Agent API POST using an independent BrowserSession or the default curl_cffi."""
    headers = _agent_headers(access_token, env=env)
    if env is not None and hasattr(env, "session"):
        return env.session.post(url, headers=headers, json=payload, timeout=timeout)
    return requests.post(url, headers=headers, json=payload, impersonate=IMPERSONATE, timeout=timeout)


# ============================================================
#  Agent registration
# ============================================================

def register_agent(
    access_token: str,
    public_key_ssh: str,
    env: Any | None = None,
    timeout: int = 15,
    display_name: str | None = None,
) -> str:
    """
    Register an agent on auth.openai.com.

    :param access_token: ChatGPT session JWT
    :param public_key_ssh: SSH format Ed25519 public key
    :return: agent_runtime_id
    """
    name = str(display_name or "").strip() or _random_agent_display_name()
    payload = {
        "abom": {
            "agent_version": AGENT_VERSION,
            "agent_harness_id": AGENT_HARNESS_ID,
            "running_location": RUNNING_LOCATION,
            # OpenAI Agent scenarios also use this round random name, to avoid always reusing the same display name.
            "display_name": name,
            "agent_name": name,
        },
        "agent_public_key": public_key_ssh,
        "display_name": name,
        "agent_name": name,
        "name": name,
    }

    r = _agent_post(
        f"{AUTHAPI_BASE}/v1/agent/register",
        access_token=access_token,
        env=env,
        timeout=timeout,
        payload=payload,
    )

    # Compatible with OpenAI strict validation of unknown fields: if the named field is not accepted, fall back to the original protocol.
    if r.status_code == 400 and any(x in (r.text or "").lower() for x in ("unknown", "unrecognized", "extra", "invalid")):
        _log("Step 3", f"OpenAI Agent the registration endpoint does not accept the name field, falling back to the original payload: {r.text[:180]}", "WARN")
        r = _agent_post(
            f"{AUTHAPI_BASE}/v1/agent/register",
            access_token=access_token,
            env=env,
            timeout=timeout,
            payload={
                "abom": {
                    "agent_version": AGENT_VERSION,
                    "agent_harness_id": AGENT_HARNESS_ID,
                    "running_location": RUNNING_LOCATION,
                },
                "agent_public_key": public_key_ssh,
            },
        )

    if r.status_code != 200:
        raise RuntimeError(f"Agent registration failed: {r.status_code} {r.text}")

    data = r.json()
    agent_runtime_id = data.get("agent_runtime_id")
    if not agent_runtime_id:
        raise RuntimeError(f"No agent_runtime_id in response: {data}")

    return agent_runtime_id


# ============================================================
#  Task registration (verify the key pair is usable)
# ============================================================

def register_task(
    access_token: str,
    agent_runtime_id: str,
    private_key_pkcs8_b64: str,
    env: Any | None = None,
    timeout: int = 15,
) -> str:
    """
    Register a task on auth.openai.com (verify the key pair is usable).
    Codex CLI this step runs automatically on startup.

    :param access_token: ChatGPT session JWT(for verification only; the actual Codex CLI signs with the key)
    :param agent_runtime_id: agent runtime ID
    :param private_key_pkcs8_b64: PKCS8 base64 private key
    :return: encrypted_task_id
    """
    # Load the private key
    pkcs8_der = base64.b64decode(private_key_pkcs8_b64)
    pem = b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(pkcs8_der) + b"-----END PRIVATE KEY-----\n"
    private_key = load_pem_private_key(pem, password=None)

    # Sign payload: {agent_runtime_id}:{timestamp}
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = f"{agent_runtime_id}:{timestamp}"
    signature = private_key.sign(payload.encode())
    signature_b64 = base64.b64encode(signature).decode()

    r = _agent_post(
        f"{AUTHAPI_BASE}/v1/agent/{agent_runtime_id}/task/register",
        access_token=access_token,
        env=env,
        timeout=timeout,
        payload={
            "timestamp": timestamp,
            "signature": signature_b64,
        },
    )

    if r.status_code != 200:
        raise RuntimeError(f"Task registration failed: {r.status_code} {r.text}")

    data = r.json()
    return data.get("encrypted_task_id", "")


# ============================================================
#  auth.json Generate
# ============================================================

def _random_agent_display_name() -> str:
    """Generate a random Agent name, so that the sub2api account name does not directly expose the email prefix."""
    adjectives = [
        "Amber", "Blue", "Cedar", "Delta", "Echo", "Falcon", "Golden", "Harbor",
        "Ivory", "Jade", "Lunar", "Nova", "Orion", "Pine", "Quartz", "River",
        "Silver", "Summit", "Vertex", "Willow",
    ]
    nouns = [
        "Agent", "Bridge", "Comet", "Drift", "Field", "Garden", "Harbor", "Island",
        "Kernel", "Lantern", "Matrix", "Node", "Orbit", "Pilot", "Relay", "Signal",
        "Stone", "Tower", "Vector", "Worker",
    ]
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"{random.choice(adjectives)} {random.choice(nouns)} {suffix}"


def generate_auth_json(
    agent_runtime_id: str,
    private_key_pkcs8_b64: str,
    account_id: str,
    chatgpt_user_id: str,
    email: str,
    plan_type: str = "free",
    chatgpt_account_is_fedramp: bool = False,
    display_name: str | None = None,
) -> dict[str, Any]:
    """
    Generate the Codex CLI auth.json.

    :return: auth.json dict
    """
    return {
        "auth_mode": "agent_identity",
        "agent_identity": {
            "agent_runtime_id": agent_runtime_id,
            "agent_private_key": private_key_pkcs8_b64,
            "account_id": account_id,
            "chatgpt_user_id": chatgpt_user_id,
            "email": email,
            "name": email,
            "plan_type": plan_type,
            "chatgpt_account_is_fedramp": chatgpt_account_is_fedramp,
        },
    }


# ============================================================
#  sub2api integration
# ============================================================

def build_sub2api_account_entry(
    auth_json: dict[str, Any],
    *,
    proxy_key: str | None = None,
) -> dict[str, Any]:
    """Convert a Codex Agent Identity auth.json into a sub2api accounts[] entry."""
    identity = auth_json.get("agent_identity") if isinstance(auth_json, dict) else None
    if not isinstance(identity, dict):
        raise ValueError("auth_json missing agent_identity")

    agent_runtime_id = str(identity.get("agent_runtime_id") or "").strip()
    agent_private_key = str(identity.get("agent_private_key") or "").strip()
    account_id = str(identity.get("account_id") or "").strip()
    chatgpt_user_id = str(identity.get("chatgpt_user_id") or "").strip()
    email = str(identity.get("email") or "").strip()
    display_name = email or str(identity.get("name") or identity.get("display_name") or "").strip() or f"agent-{agent_runtime_id[:8]}"
    plan_type = str(identity.get("plan_type") or "free").strip() or "free"
    if not agent_runtime_id or not agent_private_key:
        raise ValueError("agent_identity missing agent_runtime_id/agent_private_key")

    entry = {
        "name": display_name,
        "platform": "openai",
        "type": "agent_identity",
        "credentials": {
            "agent_runtime_id": agent_runtime_id,
            "agent_private_key": agent_private_key,
            "account_id": account_id,
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": chatgpt_user_id,
            "email": email,
            "name": email,
            "plan_type": plan_type,
            "chatgpt_account_is_fedramp": bool(identity.get("chatgpt_account_is_fedramp", False)),
        },
        "extra": {
            "email": email,
            "account_id": account_id,
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": chatgpt_user_id,
            "agent_runtime_id": agent_runtime_id,
            "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "codex_agent",
        },
        "concurrency": 10,
        "priority": 1,
        "rate_multiplier": 1,
        "auto_pause_on_expired": True,
    }
    if proxy_key:
        entry["proxy_key"] = str(proxy_key)
    return entry


def _sub2api_dedupe_key(entry: dict[str, Any]) -> str:
    credentials = entry.get("credentials") if isinstance(entry.get("credentials"), dict) else {}
    extra = entry.get("extra") if isinstance(entry.get("extra"), dict) else {}
    agent_runtime_id = credentials.get("agent_runtime_id") or extra.get("agent_runtime_id")
    if agent_runtime_id:
        return f"agent:{agent_runtime_id}"
    user_id = credentials.get("chatgpt_user_id") or extra.get("chatgpt_user_id")
    account_id = credentials.get("chatgpt_account_id") or credentials.get("account_id") or extra.get("chatgpt_account_id") or extra.get("account_id")
    if user_id and account_id:
        return f"account-user:{user_id}|{account_id}"
    email = credentials.get("email") or extra.get("email")
    if email:
        return f"email:{email}"
    return ""


def upsert_sub2api_account(
    auth_json: dict[str, Any],
    output_path: str | os.PathLike[str],
    *,
    proxy_key: str | None = None,
) -> dict[str, Any]:
    """Append/update the Agent Token in sub2api.json."""
    path = os.fspath(output_path)
    data: dict[str, Any]
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if not isinstance(loaded, dict):
            raise ValueError("sub2api config file root must be an object")
        data = loaded
    else:
        data = {}

    accounts = data.setdefault("accounts", [])
    if not isinstance(accounts, list):
        raise ValueError("sub2api accounts in the config must be an array")
    proxies = data.setdefault("proxies", [])
    if not isinstance(proxies, list):
        raise ValueError("sub2api proxies in the config must be an array")
    if proxy_key and not proxies:
        data["proxies"] = [{"proxy_key": str(proxy_key)}]

    incoming = build_sub2api_account_entry(auth_json, proxy_key=proxy_key)
    key = _sub2api_dedupe_key(incoming)
    updated = False
    for idx, existing in enumerate(accounts):
        if isinstance(existing, dict) and key and _sub2api_dedupe_key(existing) == key:
            merged = dict(existing)
            merged.update(incoming)
            # Keep manually adjusted scheduling parameters/proxy keys.
            for keep in ("concurrency", "priority", "rate_multiplier", "auto_pause_on_expired", "proxy_key"):
                if keep in existing and (keep != "proxy_key" or not proxy_key):
                    merged[keep] = existing[keep]
            accounts[idx] = merged
            updated = True
            break
    if not updated:
        accounts.append(incoming)

    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    return {
        "ok": True,
        "updated": updated,
        "added": not updated,
        "path": os.path.abspath(path),
        "total": len(accounts),
        "email": incoming.get("extra", {}).get("email"),
        "dedupe_key": key,
    }


def upload_sub2api_account(
    auth_json: dict[str, Any],
    api_url: str,
    *,
    api_token: str | None = None,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer",
    payload_mode: str = "accounts",
    proxy_key: str | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Upload/import the Agent Token directly through the sub2api HTTP API.

    Standard Wei-Shaw/sub2api uses:
      POST /api/v1/admin/accounts/import/codex-session
      {"contents":["<auth.json>"],"update_existing":true,...}

    payload_mode:
      - codex_session_import: sub2api Native Codex Session/Agent Identity import endpoint
      - account:  POST a single account object directly
      - accounts: POST {"accounts": [account]}
      - config:   POST {"accounts": [account], "proxies": [...]}
    """
    url = str(api_url or "").strip()
    if not url:
        raise ValueError("SUB2API_API_BASE is empty, cannot upload to sub2api")

    mode = str(payload_mode or "accounts").strip().lower()
    incoming: dict[str, Any] | None = None
    if mode in {"codex_session_import", "codex-session-import", "import_codex_session"}:
        identity = auth_json.get("agent_identity") if isinstance(auth_json, dict) else {}
        payload = {
            "contents": [json.dumps(auth_json, ensure_ascii=False)],
            "name": str((identity or {}).get("email") or "").strip() or str((identity or {}).get("name") or "").strip() or _random_agent_display_name(),
            "update_existing": True,
            "concurrency": 3,
            "priority": 50,
            "confirm_mixed_channel_risk": True,
        }
    elif mode == "config":
        incoming = build_sub2api_account_entry(auth_json, proxy_key=proxy_key)
        payload = {"accounts": [incoming], "proxies": ([{"proxy_key": str(proxy_key)}] if proxy_key else [])}
    elif mode == "account":
        incoming = build_sub2api_account_entry(auth_json, proxy_key=proxy_key)
        payload = incoming
    else:
        incoming = build_sub2api_account_entry(auth_json, proxy_key=proxy_key)
        payload = {"accounts": [incoming]}

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "turb-gpt-free-register/sub2api",
    }
    token = str(api_token or "").strip()
    header_name = str(auth_header or "Authorization").strip() or "Authorization"
    prefix = str(auth_prefix or "").strip()
    if token:
        headers[header_name] = f"{prefix} {token}".strip() if prefix else token

    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    status = int(getattr(resp, "status_code", 0) or 0)
    text = getattr(resp, "text", "") or ""
    try:
        body = resp.json()
    except Exception:
        body = {"text": text[:1000]}
    if status < 200 or status >= 300:
        raise RuntimeError(f"sub2api upload failed HTTP {status}: {text[:800]}")

    return {
        "ok": True,
        "uploaded": True,
        "url": url,
        "status_code": status,
        "payload_mode": mode,
        "email": (incoming or {}).get("extra", {}).get("email") or (
            (auth_json.get("agent_identity") or {}).get("email") if isinstance(auth_json, dict) else None
        ),
        "dedupe_key": _sub2api_dedupe_key(incoming) if incoming else (
            (auth_json.get("agent_identity") or {}).get("account_id") if isinstance(auth_json, dict) else None
        ),
        "response": body,
    }


# ============================================================
#  Full flow
# ============================================================

def create_codex_agent_identity(
    access_token: str,
    output_path: str | None = None,
    verify_task: bool = True,
    env: Any | None = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """
    Full flow: create a Codex Agent Identity auth.json from the ChatGPT session JWT.

    :param access_token: ChatGPT session JWT(accessToken obtained from /api/auth/session)
    :param output_path: Optional auth.json output path; when omitted only the in-memory object is returned
    :param verify_task: Whether to verify task registration (optional)
    :return: auth.json dict
    """
    _banner("Codex Agent Identity registration started")

    # Step 1: Decode the JWT to get account info
    _log("Step 1", "Decode the JWT to get account info...")
    session = get_session_from_access_token(access_token)
    account_id = session["accountId"]
    chatgpt_user_id = session["userId"]
    email = session["email"]
    plan_type = session["planType"]

    if not account_id or not chatgpt_user_id:
        raise RuntimeError(f"JWT is missing required fields: account_id={account_id}, user_id={chatgpt_user_id}")

    _log("Step 1", f"account_id={account_id}", "OK")
    _log("Step 1", f"user_id={chatgpt_user_id}", "OK")
    _log("Step 1", f"email={email}", "OK")
    _log("Step 1", f"plan_type={plan_type}", "OK")

    # Step 2: Generate an Ed25519 key pair
    _log("Step 2", "Generate an Ed25519 key pair...")
    private_key_b64, public_key_ssh = generate_ed25519_keypair()
    _log("Step 2", "Ed25519 private key generated (private key contents not printed)", "OK")
    _log("Step 2", f"public_key_fingerprint={_fingerprint(public_key_ssh)}", "OK")

    # Step 3: registration agent
    agent_display_name = _random_agent_display_name()
    _log("Step 3", f"Registering agent on auth.openai.com,display_name={agent_display_name}...")
    agent_runtime_id = register_agent(access_token, public_key_ssh, env=env, timeout=timeout, display_name=agent_display_name)
    _log("Step 3", f"agent_runtime_id={agent_runtime_id}", "OK")

    # Step 4: Verify task registration (optional)
    if verify_task:
        _log("Step 4", "Verify task registration...")
        try:
            task_id = register_task(access_token, agent_runtime_id, private_key_b64, env=env, timeout=timeout)
            _log("Step 4", f"task_id_fingerprint={_fingerprint(task_id)}", "OK")
        except Exception as e:
            _log("Step 4", f"Verification failed (auth.json is not affected): {e}", "WARN")

    # Step 5: Generate auth.json
    _log("Step 5", "Generate auth.json...")
    auth_json = generate_auth_json(
        agent_runtime_id=agent_runtime_id,
        private_key_pkcs8_b64=private_key_b64,
        account_id=account_id,
        chatgpt_user_id=chatgpt_user_id,
        email=email,
        plan_type=plan_type,
        chatgpt_account_is_fedramp=False,
        display_name=email,
    )

    if output_path:
        _log("Step 5", "Local output path ignored; credentials are persisted by SQLite", "OK")
    else:
        _log("Step 5", "auth.json returned as an in-memory object, persisted by SQLite", "OK")

    return auth_json


# ============================================================
#  Entry point
# ============================================================

def main() -> None:
    """
    Usage:

    1. Pass the JWT directly:
       python codex_agent.py --token "eyJhbGci..."

    2. Pass a JSON file (containing accessToken):
       python codex_agent.py --file session.json

    3. Interactive input:
       python codex_agent.py
    """

    import argparse

    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    parser = argparse.ArgumentParser(description="Codex Agent Identity auto-registration")
    parser.add_argument("--token", type=str, help="ChatGPT session JWT (accessToken)")
    parser.add_argument("--file", type=str, help="Path to a JSON file containing accessToken")
    parser.add_argument("--output", "-o", type=str, default=None, help="Optional output path; by default the result is only returned and saved by SQLite")
    parser.add_argument("--no-verify", action="store_true", help="Skip task registration verification")
    args = parser.parse_args()

    access_token = None

    if args.token:
        access_token = args.token
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
            access_token = data.get("accessToken") or data.get("access_token")
    else:
        # Interactive input
        print("Enter the ChatGPT session JWT (accessToken):")
        print("(obtained from chatgpt.com /api/auth/session)")
        access_token = input("> ").strip()

    if not access_token:
        print("Error: missing access_token")
        sys.exit(1)

    create_codex_agent_identity(
        access_token=access_token,
        output_path=args.output,
        verify_task=not args.no_verify,
    )


if __name__ == "__main__":
    main()
