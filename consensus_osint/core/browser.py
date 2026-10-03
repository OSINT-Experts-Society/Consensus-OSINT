"""Headless-browser fallback for challenge pages (Cloudflare "Just a moment",
Anubis / proof-of-work walls, DataDome, plain 403s that only block non-browsers).

Uses Playwright with the Chrome or Edge already installed on the machine when
possible (no browser download), otherwise Playwright's own Chromium.  Only used
for sites that came back BLOCKED, so the cost stays proportional to the number
of protected sites.  Enable with ``--browser`` (``pip install playwright``;
``playwright install chromium`` only if no Chrome/Edge is installed).
"""
from __future__ import annotations

import asyncio
import logging
import math
import time

from .errors import detect_error_page
from .http import Response
from .proxy import split_proxy

log = logging.getLogger("consensus.browser")

CHALLENGE_KINDS = {"Bot protection", "Captcha", "Access denied", "Request blocked"}


def _split_proxy(proxy: str | None) -> dict | None:
    try:
        return split_proxy(proxy)
    except ValueError as exc:
        raise ValueError("browser " + str(exc)) from None


class BrowserFetcher:
    def __init__(self, proxy: str | None = None, *, headless: bool = True, channel: str | None = None,
                 max_pages: int = 4, challenge_wait: float = 30.0, timeout: float = 35.0,
                 user_agent: str | None = None):
        self.proxy = _split_proxy(proxy)
        self.headless = headless
        self.channel = channel  # "chrome" | "msedge" | None (=try chrome, msedge, then bundled chromium)
        self.max_pages = max(1, max_pages)
        self.challenge_wait = challenge_wait
        self.timeout = timeout
        self.user_agent = user_agent
        self._pw = None
        self._browser = None
        self._context = None
        self._sem = asyncio.Semaphore(self.max_pages)
        self._lock = asyncio.Lock()
        self._close_task: asyncio.Task | None = None
        self.launched_channel: str | None = None
        self.stats = {"fetched": 0, "solved": 0, "still_blocked": 0, "errors": 0}

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        if self._close_task is not None and not self._close_task.done():
            await asyncio.shield(self._close_task)
        async with self._lock:
            if self._browser is not None:
                return
            try:
                from playwright.async_api import async_playwright  # type: ignore
            except ImportError as exc:
                raise RuntimeError("browser fallback needs: pip install playwright") from exc
            startup = asyncio.create_task(async_playwright().start())
            cancelled = False
            try:
                # Cancellation must not discard a driver that is still starting:
                # retain its handle before propagating the stop and cleaning up.
                while not startup.done():
                    try:
                        await asyncio.shield(startup)
                    except asyncio.CancelledError:
                        cancelled = True
                self._pw = startup.result()
                if cancelled:
                    raise asyncio.CancelledError
                channels = [self.channel] if self.channel else ["chrome", "msedge", None]
                last = None
                for ch in channels:
                    try:
                        kw = dict(headless=self.headless, args=["--disable-blink-features=AutomationControlled", "--no-first-run"])
                        if self.proxy:
                            kw["proxy"] = self.proxy
                        if ch:
                            kw["channel"] = ch
                        self._browser = await self._pw.chromium.launch(**kw)
                        self.launched_channel = ch or "chromium"
                        break
                    except Exception as exc:  # noqa: BLE001
                        last = exc
                        log.debug("launch %s failed: %s", ch, exc)
                if self._browser is None:
                    raise RuntimeError(f"could not launch a browser (install Chrome/Edge or run `playwright install chromium`): {last}")
                ctx_kw = dict(viewport={"width": 1366, "height": 850}, locale="en-US", java_script_enabled=True)
                if self.user_agent:
                    ctx_kw["user_agent"] = self.user_agent
                self._context = await self._browser.new_context(**ctx_kw)
                # hide the most obvious automation flag
                await self._context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
            except BaseException:
                await self.close()
                raise
            log.info("browser fallback ready (%s, %d pages)", self.launched_channel, self.max_pages)

    async def close(self) -> None:
        # Cleanup must outlive cancellation of its caller, including startup's
        # error path which already holds _lock. Never acquire that lock here.
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
        for obj in (self._context, self._browser):
            try:
                if obj is not None:
                    await obj.close()
            except asyncio.CancelledError:
                cancelled = True
            except Exception:  # noqa: BLE001
                pass
        try:
            if self._pw is not None:
                await self._pw.stop()
        except asyncio.CancelledError:
            cancelled = True
        except Exception:  # noqa: BLE001
            pass
        self._context = self._browser = self._pw = None
        if cancelled:
            raise asyncio.CancelledError

    # ------------------------------------------------------------------ fetch
    async def fetch(self, url: str, *, timeout: float | None = None) -> Response:
        """Load ``url``, wait for any JS challenge to clear, return the final page."""
        t = self.timeout if timeout is None else timeout
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) or t <= 0:
            raise ValueError("browser timeout must be finite and positive")
        if self._context is None:
            await self.start()
        t0 = time.perf_counter()
        async with self._sem:
            page = None
            statuses: list = []

            def _on_response(resp):
                try:
                    if resp.request.is_navigation_request() and resp.frame == page.main_frame:
                        statuses.append(resp.status)
                except Exception:  # noqa: BLE001
                    pass

            try:
                page = await self._context.new_page()
                page.on("response", _on_response)
                await page.goto(url, wait_until="domcontentloaded", timeout=max(1, int(t * 1000)))
                if not statuses:
                    raise RuntimeError("navigation produced no HTTP response")
                html = await self._content(page)
                deadline = time.perf_counter() + self.challenge_wait
                while _looks_like_challenge(html, statuses[-1]) and time.perf_counter() < deadline:
                    await asyncio.sleep(1.5)
                    html = await self._content(page)
                status = statuses[-1]
                final_url = page.url
                self.stats["fetched"] += 1
                if _looks_like_challenge(html, status):
                    self.stats["still_blocked"] += 1
                else:
                    self.stats["solved"] += 1
                return Response(status, html, final_url, {}, time.perf_counter() - t0, impersonated=True)
            except Exception as exc:  # noqa: BLE001
                self.stats["errors"] += 1
                return Response(0, "", url, {}, time.perf_counter() - t0, error=f"browser: {str(exc)[:160]}")
            finally:
                try:
                    if page is not None:
                        await page.close()
                except Exception:  # noqa: BLE001
                    pass

    @staticmethod
    async def _content(page) -> str:
        return await page.content()


def _looks_like_challenge(html: str, status: int) -> bool:
    err = detect_error_page(html, status)
    return err is not None and err.kind in CHALLENGE_KINDS
