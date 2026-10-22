# -*- coding: utf-8 -*-
"""Load secrets / sensitive settings from the .env in the project root.

Design goals:
  - Important API keys do not go into the default values of config/*.py tracked by git
  - config read environment variables when the module starts / reloads
  - WebUI can read and write the secret fields in .env
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _PROJECT_ROOT / ".env"
_LOADED = False

# These multi-line list fields may be explicitly overridden with an empty value, meaning [].
# For example, after the WebUI clears the proxy pool it writes PROXY_POOL="" / PROXY_POOL="[]", and it must not fall back to the default local proxy in the source.
EXPLICIT_EMPTY_LIST_ENV_KEYS = {"PROXY_POOL", "PLAN_CHECK_PROXY"}
# An empty value of these string settings has a defined meaning and must not fall back to the default in the source.
EXPLICIT_EMPTY_STRING_ENV_KEYS = {"GENERIC_API_PROXY"}

# Central registry: env key -> description (used by .env.example)
SECRET_ENV_KEYS: dict[str, str] = {
    "WEBUI_AUTH_CODE": "WebUI login authorization code",
    "WEBUI_SESSION_SECRET": "WebUI Session Cookie signing key",
    "BROWSER_USE_API_KEY": "Browser Use Cloud API Key",
    "SKYVERN_API_KEY": "Skyvern API Key",
    "ROXY_API_TOKEN": "RoxyBrowser local API Token",
    "PLAN_CHECK_PROXY": "Dedicated proxy for plan checks (may contain credentials)",
    "PLAN_CHECK_UPSTREAM_PROXY": "Local upstream proxy address for plan checks (used for the proxy chain)",
    "PROXY_POOL_UPSTREAM_PROXY": "Local upstream proxy address of the proxy pool (used for the proxy chain)",
    "QQ_IMAP_PASSWORD": "QQ mailbox IMAP authorization code (not the QQ password)",
    "GPTMAIL_API_KEY": "GPTMail API Key",
    "CLOUDFLARE_API_KEY": "Cloudflare Worker temporary email API Key / ADMIN_PASSWORD",
    "CLOUDFLARE_CUSTOM_AUTH": "Cloudflare Worker global password x-custom-auth",
    "MAIL_NEST_API_KEY": "MailNest API Key",
    "CLOUDMAIL_AUTH_TOKEN": "CloudMail Authorization Token",
    "CLOUDMAIL_PASSWORD": "CloudMail login password",
    "REMAIL_API_KEY": "Remail open API Key",
    "CPA_MANAGEMENT_KEY": "CPA management API key",
    "EXTRACT_LINK_CDK": "link extraction service CDK",
    "SUB2API_API_KEY": "sub2api management API API Key",
    "SUB2API_API_TOKEN": "sub2api management API auth token (legacy setting name, kept for compatibility)",
    "SMS_API_KEY": "Code-receiving platform API Key (e.g. GrizzlySMS)",
    "SMSBOWER_API_KEY": "SMSBower API Key",
    "L_ADMIN_AUTH_CODE": "local L code-receiving service ADMIN_AUTH_CODE",
    "H_ADMIN_AUTH_CODE": "local H code-receiving service ADMIN_AUTH_CODE",
}


def env_path() -> Path:
    return _ENV_PATH


def load_env(*, override: bool = False) -> Path:
    """Load the .env in the project root into the process environment. Can be called repeatedly (reload uses override=True).

    python-dotenv is preferred; when it is not installed the lightweight parser built into this file is used, so reading the config has no hard dependency.
    """
    global _LOADED
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover
        if _ENV_PATH.exists():
            for key, value in read_env_file().items():
                if override or key not in os.environ:
                    os.environ[key] = value
        _LOADED = True
        return _ENV_PATH

    if _ENV_PATH.exists():
        load_dotenv(dotenv_path=_ENV_PATH, override=override)
    else:
        # System environment variables are still allowed to take effect
        load_dotenv(override=override)
    _LOADED = True
    return _ENV_PATH


def ensure_loaded() -> None:
    if not _LOADED:
        load_env(override=False)


def env_str(key: str, default: str = "") -> str:
    ensure_loaded()
    value = os.getenv(key)
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip()


def _escape_env_value(value: str) -> str:
    # Always use double quotes to avoid problems with spaces/special characters
    escaped = (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "")
    )
    return f'"{escaped}"'


def read_env_file() -> dict[str, str]:
    """Parse the .env file into a dict (does not depend on os.environ)."""
    if not _ENV_PATH.exists():
        return {}
    out: dict[str, str] = {}
    for raw in _ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
            val = val.replace("\\n", "\n").replace("\\\"", '"').replace("\\\\", "\\")
        out[key] = val
    return out


def write_env_values(updates: dict[str, str]) -> list[str]:
    """Update some keys in .env, appending them when missing. Returns the list of keys actually written."""
    if not updates:
        return []

    existing_lines: list[str] = []
    if _ENV_PATH.exists():
        existing_lines = _ENV_PATH.read_text(encoding="utf-8").splitlines()

    remaining = {str(k): ("" if v is None else str(v)) for k, v in updates.items()}
    written: list[str] = []
    out_lines: list[str] = []
    key_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")

    seen_updated: set[str] = set()
    for line in existing_lines:
        m = key_re.match(line)
        if not m:
            out_lines.append(line)
            continue
        key = m.group(1)
        if key in remaining:
            out_lines.append(f"{key}={_escape_env_value(remaining.pop(key))}")
            written.append(key)
            seen_updated.add(key)
        elif key in updates and key in seen_updated:
            # Collapse duplicate keys being edited so no later stale value can
            # shadow the value the user just saved.
            continue
        else:
            out_lines.append(line)

    if remaining:
        if out_lines and out_lines[-1].strip():
            out_lines.append("")
        out_lines.append("# ---- updated by WebUI / config.env_loader ----")
        for key, value in remaining.items():
            out_lines.append(f"{key}={_escape_env_value(value)}")
            written.append(key)

    text = "\n".join(out_lines).rstrip() + "\n"
    tmp = _ENV_PATH.with_suffix(".env.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(_ENV_PATH)

    # Make the current process see the new values immediately
    load_env(override=True)
    return written


def _coerce_env_value(raw: str, default, vtype: str | None = None):
    if vtype is None:
        if isinstance(default, bool):
            vtype = "bool"
        elif isinstance(default, int) and not isinstance(default, bool):
            vtype = "int"
        elif isinstance(default, float):
            vtype = "float"
        elif isinstance(default, (list, tuple)):
            vtype = "list_str_multiline"
        else:
            vtype = "str"
    if vtype == "bool":
        return str(raw).strip().lower() in ("true", "1", "yes", "on", "y")
    if vtype == "int":
        return int(str(raw).strip())
    if vtype == "float":
        return float(str(raw).strip())
    if vtype == "list_str_multiline":
        text = str(raw)
        # compatible with old values:PROXY_POOL='["http://..."]'
        try:
            import ast
            val = ast.literal_eval(text)
            if isinstance(val, (list, tuple)):
                return [str(x).strip() for x in val if str(x).strip()]
        except Exception:
            pass
        return [line.strip() for line in text.splitlines() if line.strip()]
    return str(raw).strip()


def env_value(key: str, default=None, vtype: str | None = None):
    ensure_loaded()
    raw = os.getenv(key)
    # `.env.example` and the empty settings commonly produced by the WebUI such as `KEY=` / `KEY=""`.
    # An empty value means "not configured, use the default in config/*.py"; otherwise the bool default True
    # would be wrongly overwritten by the empty string as False, and str/list defaults would be wrongly cleared as well.
    if raw is None:
        return default
    if str(raw).strip() == "":
        if vtype == "list_str_multiline" and key in EXPLICIT_EMPTY_LIST_ENV_KEYS:
            return []
        if vtype == "str" and key in EXPLICIT_EMPTY_STRING_ENV_KEYS:
            return ""
        return default
    try:
        return _coerce_env_value(raw, default, vtype)
    except Exception:
        return default


def env_bool(key: str, default: bool = False) -> bool:
    return bool(env_value(key, default, "bool"))


def env_int(key: str, default: int = 0) -> int:
    return int(env_value(key, default, "int"))


def env_float(key: str, default: float = 0.0) -> float:
    return float(env_value(key, default, "float"))


def env_list(key: str, default: list[str] | None = None) -> list[str]:
    return list(env_value(key, default or [], "list_str_multiline"))


def apply_env_overrides(namespace: dict, schema: dict[str, str] | None = None) -> None:
    """Override the configuration constants in the module globals() with .env/environment variables.

    schema: {KEY: type}, type supports bool/int/float/str/list_str_multiline.
    When no schema is passed, the existing uppercase constants in the namespace are inferred from the type of their default value.
    """
    ensure_loaded()
    keys = schema.keys() if schema else [k for k in namespace if k.isupper()]
    for key in keys:
        if os.getenv(key) is None:
            continue
        default = namespace.get(key)
        vtype = schema.get(key) if schema else None
        namespace[key] = env_value(key, default, vtype)
