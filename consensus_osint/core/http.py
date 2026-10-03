"""Async HTTP layer used by every checker.

* httpx (HTTP/2, connection pooling, SOCKS/HTTP proxies, Tor) for the bulk of
  requests;
* optional curl_cffi browser TLS-fingerprint impersonation for sites that
  reject Python's TLS stack (an idea taken from user-scanner, Maigret and
  Naminter);
* a per-host concurrency limit so a 4,000-site scan does not hammer any one
  origin;
* one retry on transport errors for safe methods (GET, HEAD, OPTIONS).
"""
from __future__ import annotations

import asyncio
import logging
import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field

import httpx

log = logging.getLogger("consensus.http")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
]

TOR_PROXY = "socks5://127.0.0.1:9050"
DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


def _positive_timeout(value) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value) and value > 0
    except OverflowError:
        return False


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


@dataclass
class Response:
    """Transport-agnostic response."""

    status: int
    text: str
    url: str
    headers: dict = field(default_factory=dict)
    elapsed: float = 0.0
    error: str | None = None
    impersonated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None


class Http:
    """Shared client for a scan; close it with ``await aclose()``.

    Wrapper requests have an overall deadline. HTTPX responses, including
    redirects, retain at most ``max_response_bytes`` decoded bytes per response.
    A transport/decompressor may allocate a chunk before yielding it. Direct
    ``client`` calls, curl downloads and browser/solver bodies are not size-capped
    here; the latter have their own lifecycle controls.
    """

    def __init__(
        self,
        timeout: float = 15.0,
        proxy: str | None = None,
        tor: bool = False,
        user_agent: str | None = None,
        verify: bool = True,
        max_connections: int = 200,
        per_host: int = 6,
        retries: int = 1,
        impersonate: str | None = "chrome",
        http2: bool = True,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ):
        self.timeout = timeout
        self.verify = verify
        self.proxy = TOR_PROXY if tor and not proxy else proxy
        self.user_agent = user_agent
        self.retries = retries
        self.impersonate_target = impersonate
        if not _positive_timeout(timeout):
            raise ValueError("HTTP timeout must be a finite positive number")
        if type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ValueError("HTTP response limit must be a positive integer")
        self.max_response_bytes = max_response_bytes
        if any(type(value) is not int or value < 1 for value in (per_host, max_connections)):
            raise ValueError("HTTP connection limits must be positive integers")
        if type(retries) is not int or retries < 0:
            raise ValueError("HTTP retries must be a non-negative integer")
        self.per_host = per_host
        self._host_sems: dict = defaultdict(lambda: asyncio.Semaphore(per_host))
        limits = httpx.Limits(max_connections=max_connections, max_keepalive_connections=max(20, max_connections // 2))
        kwargs = dict(
            http2=http2,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            limits=limits,
            verify=verify,
            headers={"User-Agent": user_agent or random_user_agent()},
        )
        if self.proxy:
            try:
                self.client = httpx.AsyncClient(proxy=self.proxy, **kwargs)
            except TypeError:  # httpx < 0.26
                self.client = httpx.AsyncClient(proxies=self.proxy, **kwargs)
        else:
            self.client = httpx.AsyncClient(**kwargs)
        # HTTP/1.1-only fallback for servers whose HTTP/2 implementation resets streams
        self._client_h1 = None
        self._h1_kwargs = dict(kwargs, http2=False)
        self._cffi = None
        self._cffi_failed = False
        self._close_task: asyncio.Task | None = None
        # optional challenge solvers (see core.browser / core.flaresolverr)
        self.browser = None
        self.flaresolverr = None

    @property
    def has_challenge_solver(self) -> bool:
        return self.browser is not None or self.flaresolverr is not None

    async def solve_challenge(self, method: str, url: str) -> Response | None:
        """Re-fetch a challenge-protected page through FlareSolverr and/or a real browser (GET only)."""
        if method.upper() != "GET":
            return None
        if self.flaresolverr is not None:
            r = await self.flaresolverr.fetch(url)
            if r.ok and r.text:
                return r
        if self.browser is not None:
            try:
                return await self.browser.fetch(url)
            except Exception as exc:  # noqa: BLE001
                log.warning("browser fallback failed: %s", exc)
        return None

    def _h1(self) -> httpx.AsyncClient:
        if self._client_h1 is None:
            try:
                self._client_h1 = httpx.AsyncClient(proxy=self.proxy, **self._h1_kwargs) if self.proxy else httpx.AsyncClient(**self._h1_kwargs)
            except TypeError:
                self._client_h1 = httpx.AsyncClient(proxies=self.proxy, **self._h1_kwargs)
        # Both transports serve the same session. Share the CookieJar itself:
        # assigning Cookies would copy it and lose subsequent Set-Cookie changes.
        # Refresh the reference in case a caller replaced the primary cookie jar.
        self._client_h1.cookies = self.client.cookies.jar
        return self._client_h1

    # ------------------------------------------------------------------ helpers
    def _sem(self, url: str) -> asyncio.Semaphore:
        try:
            host = httpx.URL(url).host or url
        except Exception:
            host = url
        return self._host_sems[host]

    def _headers(self, headers: dict | None) -> dict:
        h = {"User-Agent": self.user_agent or random_user_agent(), "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}
        if headers:
            for k, v in headers.items():
                for existing in list(h):
                    if existing.lower() == k.lower():
                        del h[existing]
                if v is None or v == "":
                    continue
                else:
                    h[k] = v
        return h

    async def _cffi_session(self):
        if self.impersonate_target is None:
            return None
        if self._cffi is not None or self._cffi_failed:
            return self._cffi
        try:
            from curl_cffi.requests import AsyncSession  # type: ignore

            kwargs = dict(impersonate=self.impersonate_target or "chrome", timeout=self.timeout, verify=self.verify)
            if self.proxy:
                kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
            self._cffi = AsyncSession(**kwargs)
        except Exception as exc:  # noqa: BLE001
            log.debug("curl_cffi unavailable: %s", exc)
            self._cffi_failed = True
        return self._cffi

    # ------------------------------------------------------------------ request
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        data=None,
        json=None,
        follow_redirects: bool = True,
        timeout: float | None = None,
        impersonate: bool = False,
        encoding: str | None = None,
    ) -> Response:
        method = method.upper()
        hdrs = self._headers(headers)
        removed_headers = tuple(k for k, v in (headers or {}).items() if v is None or v == "")
        t = self.timeout if timeout is None else timeout
        if not _positive_timeout(t):
            raise ValueError("HTTP request timeout must be a finite positive number")
        started = time.perf_counter()
        try:
            return await asyncio.wait_for(
                self._request_with_slot(method, url, hdrs, data, json, follow_redirects, t, encoding, impersonate, removed_headers),
                timeout=t,
            )
        except asyncio.TimeoutError:
            return Response(0, "", url, {}, time.perf_counter() - started,
                            error=f"request deadline exceeded after {t}s", impersonated=impersonate)

    async def _request_with_slot(self, method, url, hdrs, data, json, follow_redirects, t, encoding, impersonate, removed_headers):
        async with self._sem(url):
            if impersonate and self.impersonate_target is not None:
                sess = await self._cffi_session()
                if sess is not None:
                    return await self._request_cffi(sess, method, url, hdrs, data, json, follow_redirects, t, encoding)
            return await self._request_httpx(method, url, hdrs, data, json, follow_redirects, t, encoding, removed_headers)

    async def _request_httpx(self, method, url, hdrs, data, json, follow_redirects, t, encoding, removed_headers=()) -> Response:
        last_err = None
        client = self.client
        for attempt in range(self.retries + 1):
            t0 = time.perf_counter()
            try:
                kw = dict(headers=hdrs, timeout=t)
                if json is not None:
                    kw["json"] = json
                elif data is not None:
                    if isinstance(data, (dict, list)):
                        kw["data"] = data
                    else:
                        kw["content"] = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
                # Changing HTTP protocol must not change the current session's
                # default headers, credentials, cookies or redirect policy.
                request = self.client.build_request(method, url, **kw)
                for name in removed_headers:
                    request.headers.pop(name, None)
                for redirect in range(self.client.max_redirects + 1):
                    send_options = {"auth": None if redirect else self.client.auth}
                    r = await client.send(request, stream=True, follow_redirects=False, **send_options)
                    try:
                        body = bytearray()
                        async for chunk in r.aiter_bytes():
                            if len(chunk) > self.max_response_bytes - len(body):
                                return Response(0, "", str(r.url), {}, time.perf_counter() - t0,
                                                error=f"response exceeds {self.max_response_bytes} bytes")
                            body.extend(chunk)
                        if follow_redirects and r.next_request is not None:
                            if redirect == self.client.max_redirects:
                                return Response(0, "", str(r.url), {}, time.perf_counter() - t0,
                                                error="too many redirects")
                            request = r.next_request
                            continue
                        try:
                            text = body.decode(encoding or r.encoding or "utf-8", "replace")
                        except LookupError:
                            text = body.decode("utf-8", "replace")
                        return Response(r.status_code, text, str(r.url), dict(r.headers), time.perf_counter() - t0)
                    finally:
                        await r.aclose()
            except httpx.TimeoutException:
                last_err = f"timeout after {t}s"
                log.debug("timeout %s %s", method, url)
                break
            except (httpx.TransportError, httpx.RemoteProtocolError) as exc:
                last_err = f"{type(exc).__name__}: {exc}"[:200]
                if attempt < self.retries and method in {"GET", "HEAD", "OPTIONS"}:
                    if isinstance(exc, httpx.RemoteProtocolError) or "StreamReset" in last_err or "h2" in last_err.lower():
                        client = self._h1()
                    await asyncio.sleep(0.3 + random.random() * 0.5)
                    continue
                break
            except Exception as exc:  # noqa: BLE001
                last_err = f"{type(exc).__name__}: {exc}"[:200]
                break
        return Response(0, "", url, {}, 0.0, error=last_err or "request failed")

    async def _request_cffi(self, sess, method, url, hdrs, data, json, follow_redirects, t, encoding) -> Response:
        t0 = time.perf_counter()
        hdrs = {k: v for k, v in hdrs.items() if k.lower() != "user-agent"}
        try:
            kw = dict(headers=hdrs, allow_redirects=follow_redirects, timeout=t)
            if json is not None:
                kw["json"] = json
            elif data is not None:
                kw["data"] = data
            r = await sess.request(method, url, **kw)
            text = r.text if encoding is None else r.content.decode(encoding, "replace")
            return Response(r.status_code, text, str(r.url), dict(r.headers), time.perf_counter() - t0, impersonated=True)
        except Exception as exc:  # noqa: BLE001
            return Response(0, "", url, {}, time.perf_counter() - t0, error=f"{type(exc).__name__}: {exc}"[:200], impersonated=True)

    async def get(self, url: str, **kw) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Response:
        return await self.request("POST", url, **kw)

    async def aclose(self) -> None:
        # A second Ctrl+C must not interrupt cleanup of the remaining clients.
        if self._close_task is None or self._close_task.done():
            self._close_task = asyncio.create_task(self._close_resources())
        task = self._close_task
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
        try:
            task.result()
        except asyncio.CancelledError:
            cancelled = True
        if cancelled:
            raise asyncio.CancelledError

    async def _close_resources(self) -> None:
        cancelled = False
        for solver in (self.browser, self.flaresolverr):
            if solver is not None:
                try:
                    await solver.close()
                except asyncio.CancelledError:
                    cancelled = True
                except Exception:  # noqa: BLE001
                    pass
        for c in (self.client, self._client_h1):
            if c is None:
                continue
            try:
                await c.aclose()
            except asyncio.CancelledError:
                cancelled = True
            except Exception:  # noqa: BLE001
                pass
        if self._cffi is not None:
            try:
                await self._cffi.close()
            except asyncio.CancelledError:
                cancelled = True
            except Exception:  # noqa: BLE001
                pass
        if cancelled:
            raise asyncio.CancelledError

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()
