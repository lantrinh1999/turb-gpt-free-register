"""Common parsing helpers for HTTP and SOCKS proxy URLs."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


SUPPORTED_PROXY_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})


@dataclass(frozen=True)
class ProxySpec:
    raw: str
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""


def parse_proxy_url(value: str, *, allow_bare: bool = False) -> ProxySpec:
    text = str(value or "").strip()
    if not text:
        raise ValueError("Proxy address is empty")
    text = text.replace("\\@", "@")
    if allow_bare and "://" not in text:
        text = f"socks5://{text}"
    parsed = urlsplit(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in SUPPORTED_PROXY_SCHEMES:
        raise ValueError(f"Unsupported proxy protocol: {scheme or '-'}")
    if not parsed.hostname:
        raise ValueError("Proxy format is missing host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid proxy port") from exc
    if not port or not 1 <= port <= 65535:
        raise ValueError("Proxy format is missing a valid port")
    return ProxySpec(
        raw=text,
        scheme=scheme,
        host=parsed.hostname,
        port=port,
        username=unquote(parsed.username or ""),
        password=unquote(parsed.password or ""),
    )


def mask_proxy_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        spec = parse_proxy_url(text)
    except ValueError:
        return "***"
    auth = "***:***@" if spec.username or spec.password else ""
    return f"{spec.scheme}://{auth}{spec.host}:{spec.port}"


def validate_proxy_lines(lines) -> None:
    for index, line in enumerate(lines or [], 1):
        try:
            parse_proxy_url(line)
        except ValueError as exc:
            raise ValueError(f"Proxy pool line {index} has an invalid format: {exc}") from exc


def diagnose_proxy_endpoint(value: str, *, timeout: float = 2.0) -> str:
    try:
        spec = parse_proxy_url(value)
        with socket.create_connection((spec.host, spec.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            response = sock.recv(512)
    except Exception:
        return ""
    if response.startswith(b"HTTP/"):
        first_line = response.splitlines()[0].decode("latin1", errors="replace")
        return f"Proxy port returned {first_line}; the current port may not be SOCKS5, or authorization/whitelist does not match"
    if response[:1] == b"\x05":
        return "SOCKS5 handshake response is normal; the username/password or target address may have been rejected"
    return "Proxy port returned a non-SOCKS5 response, confirm the protocol and port"
