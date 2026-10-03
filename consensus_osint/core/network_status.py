"""Observe public egress without sending identifiers or falling back from a proxy."""
from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from urllib.request import getproxies

import httpx

IP_ENDPOINT = "https://api64.ipify.org"


@dataclass(frozen=True)
class NetworkStatus:
    public_ip: str = "checking…"
    proxy_ip: str = "not configured"
    proxy_status: str = "off"


async def observe_ip(*, proxy=None, trust_env=False):
    """One bounded request. Never return a response body or a credential in errors."""
    async def request():
        async with httpx.AsyncClient(proxy=proxy, trust_env=trust_env, timeout=4,
                                     follow_redirects=False) as client:
            async with client.stream("GET", IP_ENDPOINT) as response:
                if response.status_code != 200:
                    return f"unavailable (HTTP {response.status_code})"
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 128:
                        return "invalid response"
                address = ipaddress.ip_address(body.decode("ascii").strip())
                return str(address) if address.is_global else "invalid response"

    try:
        return await asyncio.wait_for(request(), timeout=5)
    except (asyncio.TimeoutError, httpx.TimeoutException):
        return "timed out"
    except Exception:  # A connectivity indicator must not interrupt the application.
        return "unavailable"


def system_proxy_configured():
    proxies = getproxies()
    return bool(proxies.get("https") or proxies.get("all"))


async def check_network(proxy=None, *, system_proxy=False):
    if proxy or system_proxy:
        public, routed = await asyncio.gather(observe_ip(), observe_ip(proxy=proxy, trust_env=system_proxy))
        try:
            ipaddress.ip_address(routed)
            state = "observed" if proxy else "system route observed"
        except ValueError:
            state = "unverified"
        return NetworkStatus(public, routed, state)
    return NetworkStatus(await observe_ip())
