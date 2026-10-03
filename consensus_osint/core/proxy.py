"""Parse configured browser/solver proxy URLs without losing route credentials."""
from __future__ import annotations

from urllib.parse import unquote, urlsplit


def split_proxy(proxy: str | None) -> dict | None:
    """Separate the server and decoded credentials for browser and solver APIs."""
    if proxy is None:
        return None
    try:
        if not isinstance(proxy, str) or not proxy or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in proxy):
            raise ValueError
        u = urlsplit(proxy)
        if u.scheme not in {"http", "https", "socks4", "socks5"} or not u.hostname or u.path not in {"", "/"} or u.query or u.fragment:
            raise ValueError
        host = u.hostname
        if any(c in host for c in "\\%") or u.netloc.endswith(":"):
            raise ValueError
        port = u.port
        if port == 0:
            raise ValueError
        username = unquote(u.username) if u.username is not None else None
        password = unquote(u.password) if u.password is not None else None
        if any(ord(c) < 32 or ord(c) == 127 for value in (username, password) if value is not None for c in value):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("proxy must be a valid HTTP(S) or SOCKS4/5 URL") from None
    server = f"{u.scheme}://{'[' + host + ']' if ':' in host else host}"
    if port is not None:
        server += f":{port}"
    out = {"server": server}
    if username is not None:
        out["username"] = username
    if password is not None:
        out["password"] = password
    return out
