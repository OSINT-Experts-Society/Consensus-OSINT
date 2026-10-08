"""Async orchestration: fan a query out over sites and code modules under a global
concurrency limit and a per-host limit, streaming results to a callback as they
complete.

The per-host limit is what keeps a scan polite.  Several entries can legitimately
target one host - a GitHub profile, its gists, its sponsors page - and a query fans
out to thousands of sites at once; without the limit every entry for a host fires
together, which looks like an attack and earns the block that then hides real
results."""
from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import re
from collections import deque
from collections.abc import Callable, Iterable
from urllib.parse import urlparse

from .decoding import capture_decoding
from .http import Http
from .models import Finding
from .modules import Context, Module
from .scan_control import checkpoint
from .sitesdb import Site
from .username_checker import check_site

log = logging.getLogger("consensus.runner")

#: Simultaneous requests allowed to any one host.
DEFAULT_PER_HOST = 4


def host_of(url: str | None) -> str:
    """The host a request goes to, normalised so mirrors share one limit."""
    if not url:
        return ""
    try:
        host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""
    return re.sub(r"^(www|m|mobile)\.", "", host)


async def _gather_stream(coros: list, hosts: list, concurrency: int, on_result: Callable | None,
                         delay: float = 0.0, per_host: int = DEFAULT_PER_HOST) -> list:
    limit = max(1, concurrency)
    results: list = []
    start_lock = asyncio.Lock()
    last_start: float | None = None

    async def wait_for_start():
        nonlocal last_start
        if delay <= 0:
            await checkpoint()
            return
        async with start_lock:
            await checkpoint()
            loop = asyncio.get_running_loop()
            if last_start is not None:
                # Event-loop timers may wake up one clock-resolution early.
                # Recheck the deadline before releasing the next request.
                while (remaining := last_start + delay - loop.time()) > 0:
                    await asyncio.sleep(remaining)
            await checkpoint()
            last_start = loop.time()

    async def wrapped(coro):
        try:
            await wait_for_start()
            return await coro
        finally:
            if inspect.iscoroutine(coro):
                coro.close()

    if len(coros) != len(hosts):
        for coro in coros:
            if inspect.iscoroutine(coro):
                coro.close()
        raise ValueError("each check must have a corresponding host")
    # Schedule only runnable work, rather than thousands of tasks waiting on
    # semaphores. Rotate eligible hosts so a busy host cannot block other sites.
    queues = {}
    for coro, host in zip(coros, hosts, strict=True):
        queues.setdefault(host, deque()).append(coro)
    ready = deque(queues)
    queued = set(queues)
    active = dict.fromkeys(queues, 0)
    tasks = {}
    completed = asyncio.Queue()

    def offer(host):
        host_limit = max(1, per_host) if host else limit
        if queues[host] and active[host] < host_limit and host not in queued:
            ready.append(host)
            queued.add(host)

    def fill():
        while ready and len(tasks) < limit:
            host = ready.popleft()
            queued.remove(host)
            coro = queues[host].popleft()
            active[host] += 1
            task = asyncio.create_task(wrapped(coro))
            tasks[task] = host
            task.add_done_callback(completed.put_nowait)
            offer(host)

    try:
        fill()
        while tasks:
            fut = await completed.get()
            host = tasks.pop(fut)
            active[host] -= 1
            offer(host)
            try:
                f = fut.result()
            except Exception:  # noqa: BLE001
                log.debug("task failed", exc_info=True)
            else:
                results.append(f)
                if on_result:
                    try:
                        on_result(f)
                    except Exception:  # noqa: BLE001
                        log.debug("on_result callback failed", exc_info=True)
            fill()
    finally:
        for t in tasks:
            t.cancel()
        cancelled = False
        if tasks:
            cleanup = asyncio.gather(*tasks, return_exceptions=True)
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    # Repeated Stop/Ctrl-C must not interrupt client cleanup
                    # or strand the unscheduled coroutine objects below.
                    cancelled = True
        for coro in coros:
            if inspect.iscoroutine(coro):
                coro.close()
        if cancelled:
            raise asyncio.CancelledError
    return results


async def _checked(call, query: str, item, query_type: str) -> Finding:
    """Keep unexpected checker failures visible in the scan and its counts."""
    with capture_decoding() as decoding:
        try:
            finding = await call()
            if not isinstance(finding, Finding):
                raise TypeError("checker must return a Finding")
        except Exception as exc:  # cancellation still propagates
            log.debug("checker %s failed", item.id, exc_info=True)
            finding = Finding.error_result(query, query_type, item.name, item.id,
                                           f"{type(exc).__name__}: {exc}",
                                           source=getattr(item, "source", "sites-db"),
                                           category=getattr(item, "category", "misc"))
        if decoding[0]:
            finding.extra["_text_decoding"] = {
                "warnings": decoding[0],
                "message": "Some source characters were replaced during decoding; inspect returned text.",
            }
        finding.extra["_lookup_id"] = ("module:" if isinstance(item, Module) else "site:") + item.id
        return finding


async def run_sites(
    query: str,
    sites: Iterable[Site],
    http: Http,
    *,
    concurrency: int = 100,
    on_result: Callable | None = None,
    extract: bool = True,
    query_type: str = "username",
    delay: float = 0.0,
    per_host: int = DEFAULT_PER_HOST,
) -> list:
    sites = list(sites)
    coros = [_checked(functools.partial(check_site, s, query, http, extract=extract, query_type=query_type),
                      query, s, query_type) for s in sites]
    hosts = [host_of(s.url_probe or s.url) for s in sites]
    return await _gather_stream(coros, hosts, concurrency, on_result, delay, per_host)


async def run_modules(
    query: str,
    modules: Iterable[Module],
    ctx: Context,
    *,
    concurrency: int = 40,
    on_result: Callable | None = None,
    delay: float = 0.0,
    per_host: int = DEFAULT_PER_HOST,
) -> list:
    modules = list(modules)
    coros = [_checked(functools.partial(m.run, query, ctx), query, m, m.kind) for m in modules]
    hosts = [host_of(m.url_main) for m in modules]
    return await _gather_stream(coros, hosts, concurrency, on_result, delay, per_host)


async def run_all(
    query: str,
    *,
    sites: Iterable[Site] = (),
    modules: Iterable[Module] = (),
    http: Http,
    ctx: Context,
    concurrency: int = 100,
    module_concurrency: int | None = None,
    on_result: Callable | None = None,
    extract: bool = True,
    query_type: str = "username",
    delay: float = 0.0,
    per_host: int = DEFAULT_PER_HOST,
) -> list:
    """Run data-driven sites and code modules together."""
    sites = list(sites)
    modules = list(modules)
    module_sem = asyncio.Semaphore(max(1, module_concurrency or concurrency))

    async def module_run(module):
        async with module_sem:
            await checkpoint()
            return await _checked(functools.partial(module.run, query, ctx), query, module, module.kind)

    coros = [_checked(functools.partial(check_site, s, query, http, extract=extract, query_type=query_type),
                      query, s, query_type) for s in sites]
    coros += [module_run(m) for m in modules]
    hosts = [host_of(s.url_probe or s.url) for s in sites] + [host_of(m.url_main) for m in modules]
    return await _gather_stream(coros, hosts, concurrency, on_result, delay, per_host)


def summarize(findings: list) -> dict:
    counts: dict = {}
    for f in findings:
        counts[f.status.value] = counts.get(f.status.value, 0) + 1
    counts["total"] = len(findings)
    return counts
