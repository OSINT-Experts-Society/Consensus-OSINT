"""FlareSolverr client: hand challenge-protected URLs to a FlareSolverr instance
(a headless Chrome that solves Cloudflare challenges), as Maigret's
``--cloudflare-bypass`` does.

    docker run -d -p 127.0.0.1:8191:8191 ghcr.io/flaresolverr/flaresolverr:latest
    consensus user fred --flaresolverr http://localhost:8191
"""
from __future__ import annotations

import logging
import time

import httpx

from .http import Response, _positive_timeout
from .proxy import split_proxy

log = logging.getLogger("consensus.flaresolverr")


class FlareSolverr:
    def __init__(self, endpoint: str = "http://localhost:8191", proxy: str | None = None, timeout: float = 75.0):
        if not _positive_timeout(timeout):
            raise ValueError("solver timeout must be finite and positive")
        ep = endpoint.rstrip("/")
        self.endpoint = ep if ep.endswith("/v1") else ep + "/v1"
        self.proxy = proxy
        self._proxy_param()  # Validate before allocating a client; never fall back to a direct route.
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout + 15, trust_env=False)
        self.stats = {"fetched": 0, "solved": 0, "failed": 0}

    def _proxy_param(self) -> dict | None:
        parsed = split_proxy(self.proxy)
        if parsed is None:
            return None
        return {"url": parsed["server"], **{k: v for k, v in parsed.items() if k != "server"}}

    async def fetch(self, url: str, *, method: str = "GET", data=None, timeout: float | None = None) -> Response:
        t0 = time.perf_counter()
        if not isinstance(method, str) or method.upper() not in ("GET", "POST"):
            return Response(0, "", url, {}, 0, error="flaresolverr: unsupported request method")
        t = self.timeout if timeout is None else timeout
        if not _positive_timeout(t):
            return Response(0, "", url, {}, 0, error="flaresolverr: invalid timeout")
        if method.upper() == "POST" and data is not None and not isinstance(data, str):
            return Response(0, "", url, {}, 0, error="flaresolverr: structured request bodies are unsupported")
        try:
            body = {"cmd": "request.post" if method.upper() == "POST" else "request.get", "url": url,
                    "maxTimeout": int(t * 1000)}
            if method.upper() == "POST" and data is not None:
                body["postData"] = data
            prox = self._proxy_param()
            if prox:
                body["proxy"] = prox
            r = await self._client.post(self.endpoint, json=body, timeout=t + 15)
            self.stats["fetched"] += 1
            if r.status_code != 200:
                self.stats["failed"] += 1
                return Response(0, "", url, {}, time.perf_counter() - t0,
                                error=f"flaresolverr: solver endpoint returned HTTP {r.status_code}")
            payload = r.json()
        except Exception as exc:  # noqa: BLE001
            self.stats["failed"] += 1
            return Response(0, "", url, {}, time.perf_counter() - t0, error=f"flaresolverr: {str(exc)[:160]}")
        if not isinstance(payload, dict):
            self.stats["failed"] += 1
            return Response(0, "", url, {}, time.perf_counter() - t0, error="flaresolverr: invalid response object")
        if payload.get("status") != "ok":
            self.stats["failed"] += 1
            return Response(0, "", url, {}, time.perf_counter() - t0,
                            error=f"flaresolverr: {str(payload.get('message') or payload)[:160]}")
        sol = payload.get("solution") or {}
        if (not isinstance(sol, dict) or type(sol.get("status")) is not int
                or not 100 <= sol["status"] <= 599 or not isinstance(sol.get("response"), str)
                or not isinstance(sol.get("url", url), str)
                or not isinstance(sol.get("headers", {}), dict)):
            self.stats["failed"] += 1
            return Response(0, "", url, {}, time.perf_counter() - t0, error="flaresolverr: invalid solution object")
        self.stats["solved"] += 1
        return Response(int(sol.get("status") or 200), sol.get("response") or "", sol.get("url") or url,
                        dict(sol.get("headers") or {}), time.perf_counter() - t0, impersonated=True)

    async def close(self) -> None:
        try:
            await self._client.aclose()
        except Exception:  # noqa: BLE001
            pass
