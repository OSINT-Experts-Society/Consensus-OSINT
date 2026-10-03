"""Consensus adapter for the vendored user-scanner modules.

user-scanner (https://github.com/kaifcodec/user-scanner, MIT) ships ~290
username modules under ``user_scan/<category>/<site>.py`` and ~175 e-mail
modules under ``email_scan/<category>/<site>.py``.  Every module defines one
``validate_<site>(target)`` function - synchronous for nearly all username
modules, ``async`` for the e-mail modules - returning a user-scanner
``Result`` whose ``extra`` / ``media`` dicts carry scraped profile metadata
(name, bio, followers, avatar ...).

This adapter wraps each of them as a :class:`~consensus_osint.core.modules.Module`:

* ``id``    ``us-user-<category>-<site>`` / ``us-email-<category>-<site>``
* ``name``  ``helpers.get_site_name()`` of the module (``Github``, ``X (Twitter)``)
* ``kind``  ``"username"`` or ``"email"``
* ``loud``  ``helpers.is_loud()`` - modules that may trigger a password-reset mail
* ``nsfw``  category ``adult``

``check()`` pushes the scan context into user-scanner's process-wide settings
(``helpers.set_global_timeout`` / ``helpers.set_proxy_manager``, applied once
per distinct timeout/proxy pair), runs the validate function (sync functions in
a thread pool, exactly like upstream's ``_async_worker``) and maps the
``Result`` onto a :class:`~consensus_osint.core.models.Finding`::

    TAKEN -> FOUND, AVAILABLE -> NOT_FOUND, SKIPPED -> SKIPPED,
    ERROR -> ERROR, or BLOCKED / RATE_LIMITED when the reason says so

``result.url`` becomes ``finding.url``, ``result.extra`` is copied into
``finding.extra`` and ``result.media`` lands in ``finding.extra["media"]``.

Upstream makes its e-mail modules honour ``--proxy`` / ``-t`` by monkey-patching
``httpx.Client`` / ``httpx.AsyncClient`` process-wide at import time of
``core.email_orchestrator`` (which this adapter therefore never imports).  The
same technique is used here but gated on a :mod:`contextvars` flag: only
clients created *while a user-scanner module is running* receive the proxy and
timeout. HTTPX send calls in the active context also cap per-phase timeout
extensions, preserving smaller explicit limits. Calls outside that context are
untouched. This does not impose an overall deadline or response-size cap on raw
vendor HTTPX calls, nor does it cover vendor curl/urllib transports.

Different scan contexts wait because upstream timeout/proxy settings are global;
checks sharing one Context can overlap. Cancelling an awaiting task does not
release those settings while its worker thread is still running.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import copy
import functools
import importlib
import inspect
import logging
import math
import re
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType
from typing import Any

from consensus_osint.core.models import Finding, Status
from consensus_osint.core.modules import Context, Module

log = logging.getLogger("consensus.adapters.user_scanner")

VENDOR_PKG = "consensus_osint.vendor.user_scanner"
SOURCE = "user-scanner"
METHOD = "user-scanner module"
DEFAULT_THREADS = 128          # thread pool for the synchronous username modules

__all__ = [
    "load_modules",
    "build_module",
    "import_failures",
    "load_pivots_module",
    "load_patterns_module",
    "VENDOR_PKG",
    "SOURCE",
    "METHOD",
]


# ---------------------------------------------------------------------------
# vendored package access (imported lazily so importing this adapter is cheap
# and never fails because of a missing optional upstream dependency)
# ---------------------------------------------------------------------------
def _helpers() -> ModuleType:
    return importlib.import_module(f"{VENDOR_PKG}.core.helpers")


def _result_mod() -> ModuleType:
    return importlib.import_module(f"{VENDOR_PKG}.core.result")


def load_pivots_module() -> ModuleType | None:
    """The vendored ``core.pivots`` (username / e-mail pivot extraction) or None."""
    try:
        return importlib.import_module(f"{VENDOR_PKG}.core.pivots")
    except Exception as exc:  # noqa: BLE001
        log.warning("user-scanner pivots module unavailable: %s", exc)
        return None


def load_patterns_module() -> ModuleType | None:
    """The vendored ``core.patterns`` (``john[a-z]{1-2}`` username expansion) or None."""
    try:
        return importlib.import_module(f"{VENDOR_PKG}.core.patterns")
    except Exception as exc:  # noqa: BLE001
        log.warning("user-scanner patterns module unavailable: %s", exc)
        return None


# ---------------------------------------------------------------------------
# module discovery
# ---------------------------------------------------------------------------
_IMPORT_FAILURES: list = []          # (dotted module path, error message)
_MODULES: list | None = None
_LOAD_LOCK = threading.Lock()


def load_modules() -> list:
    """Import every vendored ``user_scan`` / ``email_scan`` module and wrap it (cached)."""
    global _MODULES
    if _MODULES is None:
        with _LOAD_LOCK:
            if _MODULES is None:
                _MODULES = _discover()
    return list(_MODULES)


def import_failures() -> list:
    """``(dotted module path, error)`` for every upstream module that could not be loaded."""
    return list(_IMPORT_FAILURES)


def _module_id(category: str, stem: str, is_email: bool) -> str:
    return f"us-{'email' if is_email else 'user'}-{(category or 'misc').lower()}-{stem.lower()}"


_URL_RE = re.compile(r"https?://[^\s\"'()<>\[\]\\]+")
_URL_LINE_RE = re.compile(r"^\s*(show_url|display_url|profile_url|url|base_url|api_url)\s*=", re.M)
_SHOW_LINE_RE = re.compile(r"^\s*(show_url|display_url|profile_url)\s*=", re.M)


def _guess_url_main(func: Callable, stem: str) -> str | None:
    """The service URL of an upstream module, read from its own source.

    Upstream modules never declare their site; the URL sits in a ``show_url`` /
    ``url`` assignment inside ``validate_<site>``.  Knowing it is what lets the
    (kind, host) de-duplication and ``--site`` treat these modules like every other
    check.  Prefers the display URL, then any URL whose host carries the module's
    name (so a link to GitHub inside another site's module does not win).
    """
    from ..core.selected_profile_guards import declared_profile
    if declared := declared_profile(func):
        return declared
    try:
        src = inspect.getsource(func)
    except (OSError, TypeError):
        return None
    lines = src.splitlines()
    # the human page (show_url) names the service; an API host (api.example.com) is the same service
    shown = [ln for ln in lines if _SHOW_LINE_RE.match(ln)]
    preferred = [ln for ln in lines if _URL_LINE_RE.match(ln)]
    candidates = ([u for ln in shown for u in _URL_RE.findall(ln)]
                  or [u for ln in preferred for u in _URL_RE.findall(ln)] or _URL_RE.findall(src))
    if not candidates:
        # the URL may live in a module-level constant (BASE_URL = "https://...")
        try:
            whole = inspect.getsource(sys.modules[func.__module__])
        except (OSError, TypeError, KeyError):
            return None
        preferred = [ln for ln in whole.splitlines() if _URL_LINE_RE.match(ln) or re.match(r"^[A-Z_]*URL[A-Z_]*\s*=", ln)]
        shown = [ln for ln in whole.splitlines() if _SHOW_LINE_RE.match(ln)]
        candidates = ([u for ln in shown for u in _URL_RE.findall(ln)]
                      or [u for ln in preferred for u in _URL_RE.findall(ln)] or _URL_RE.findall(whole))
        if not candidates:
            return None
    words = [w for w in re.split(r"[^a-z0-9]+", stem.lower()) if len(w) >= 3]
    for u in candidates:
        host = u.split("//", 1)[1].split("/", 1)[0].lower()
        if any(w in host for w in words):
            return u.replace("{user}", "{username}").replace("{target}", "{username}").replace("{encoded_user}", "{username}")
    return candidates[0].replace("{user}", "{username}").replace("{target}", "{username}").replace("{encoded_user}", "{username}")


def _discover() -> list:
    helpers = _helpers()
    _IMPORT_FAILURES.clear()
    try:
        from .rules_adapter import replaced_ids

        replaced = replaced_ids()
    except Exception:  # noqa: BLE001
        replaced = set()
    out: list = []
    for is_email, folder in ((False, "user_scan"), (True, "email_scan")):
        try:
            categories = helpers.load_categories(is_email=is_email)
        except Exception as exc:  # noqa: BLE001
            log.warning("user-scanner: cannot list %s categories: %s", folder, exc)
            continue
        for category, path in sorted(categories.items()):
            for file in sorted(path.glob("*.py")):
                if file.name == "__init__.py":
                    continue
                if _module_id(category, file.stem, is_email) in replaced:
                    continue            # a data rule supersedes this module (rules.json "replaces")
                dotted = f"{VENDOR_PKG}.{folder}.{category}.{file.stem}"
                try:
                    pymod = importlib.import_module(dotted)
                except Exception as exc:  # noqa: BLE001 - third-party module code
                    _IMPORT_FAILURES.append((dotted, f"{type(exc).__name__}: {exc}"))
                    log.warning("user-scanner module %s failed to import: %s", dotted, exc)
                    continue
                module = build_module(pymod, category, is_email)
                if module is None:
                    _IMPORT_FAILURES.append((dotted, "no validate_ function"))
                    continue
                out.append(module)
    log.debug("user-scanner adapter: %d modules, %d import failures", len(out), len(_IMPORT_FAILURES))
    return out


@dataclass(frozen=True)
class _Meta:
    id: str
    name: str
    kind: str
    category: str
    loud: bool
    nsfw: bool
    func: Callable
    is_coroutine: bool


def build_module(pymod: ModuleType, category: str, is_email: bool, func: Callable | None = None) -> Module | None:
    """Wrap one upstream python module as a :class:`Module` (None when it has no ``validate_`` function)."""
    helpers = _helpers()
    func = func or helpers.get_scan_func(pymod)
    if func is None:
        return None
    name = helpers.get_site_name(pymod)
    kind = "email" if is_email else "username"
    stem = pymod.__name__.rsplit(".", 1)[-1]
    category = (category or "misc").lower()
    meta = _Meta(
        id=_module_id(category, stem, is_email),
        name=name,
        kind=kind,
        category=category,
        loud=bool(helpers.is_loud(name, is_email)),
        nsfw=category == "adult",
        func=func,
        is_coroutine=inspect.iscoroutinefunction(func),
    )

    async def check(query: str, ctx: Context) -> Finding:
        return await _run(meta, query, ctx)

    check.__name__ = f"check_{stem}"
    return Module(
        id=meta.id,
        name=name,
        kind=kind,
        check=check,
        category=category,
        source=SOURCE,
        url_main=_guess_url_main(func, stem),   # the Result carries the exact profile URL; this is the service
        loud=meta.loud,
        nsfw=meta.nsfw,
        method=METHOD,
    )


# ---------------------------------------------------------------------------
# running a module
# ---------------------------------------------------------------------------
_ACTIVE: contextvars.ContextVar = contextvars.ContextVar("consensus_user_scanner_active", default=False)
_ACTIVE_CONTEXT: contextvars.ContextVar = contextvars.ContextVar("consensus_user_scanner_context", default=None)
_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None
_NESTED_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None
_SETTINGS_LOCK = threading.Lock()
_RUN_LOCK = threading.Lock()        # protects active context and worker count across event loops
_RUN_CONTEXT: Context | None = None
_RUN_COUNT = 0
_applied: tuple | None = None     # (timeout, proxy) last pushed into user-scanner's globals
_hook_installed = False


def notifications_allowed() -> bool:
    """Read notification permission from this invocation, never process arguments."""
    ctx = _ACTIVE_CONTEXT.get()
    return ctx is not None and ctx.allow_loud is True


def _enter_context(ctx: Context) -> bool:
    global _RUN_CONTEXT, _RUN_COUNT
    with _RUN_LOCK:
        if _RUN_COUNT and _RUN_CONTEXT is not ctx:
            return False
        if not _RUN_COUNT:
            _apply_context(ctx)
            _RUN_CONTEXT = ctx
        _RUN_COUNT += 1
        return True


def _leave_context() -> None:
    global _RUN_CONTEXT, _RUN_COUNT
    with _RUN_LOCK:
        _RUN_COUNT -= 1
        if not _RUN_COUNT:
            _RUN_CONTEXT = None
            # Cancelled awaiters can leave blocking/nested workers running. Their
            # leases keep the transports alive until their actual completion.
            # Hold the entry lock until cleanup ends so a new context cannot use
            # an old cookie jar or a client that is being closed.
            for name in ("orchestrator", "impersonate"):
                module = sys.modules.get(f"{VENDOR_PKG}.core.{name}")
                if module is not None:
                    try:
                        module.close_cached_transports()
                    except Exception:
                        log.warning("Could not close user-scanner %s transports", name, exc_info=True)


async def _thread_call(ctx: Context, pool, func, *args, **kwargs):
    """Keep settings leased until a submitted thread finishes or is cancelled in its queue."""
    if not _enter_context(ctx):  # the caller already owns this context
        raise RuntimeError("user-scanner worker lost its context")
    call = functools.partial(contextvars.copy_context().run, func, *args, **kwargs)
    try:
        future = pool.submit(call)
    except BaseException:
        _leave_context()
        raise
    # A callback also runs when shutdown cancels work before it starts. A worker's
    # finally block alone would leak the lease in that case.
    future.add_done_callback(lambda done: _leave_context())
    wrapped = asyncio.wrap_future(future)
    wrapped.add_done_callback(lambda done: None if done.cancelled() else done.exception())
    return await asyncio.shield(wrapped)


def _install_worker_hook() -> None:
    """Lease settings for vendor helpers that start their own asyncio.to_thread work."""
    global _NESTED_EXECUTOR
    with _SETTINGS_LOCK:
        if getattr(asyncio.to_thread, "_consensus_user_scanner_worker_hook", False):
            return
        original = asyncio.to_thread
        # Keep nested work separate: a synchronous module can itself await an
        # async helper, so sharing the outer pool could exhaust all its workers.
        _NESTED_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=32, thread_name_prefix="consensus-user-scanner-nested"
        )
        pool = _NESTED_EXECUTOR

        @functools.wraps(original)
        async def to_thread(func, /, *args, **kwargs):
            ctx = _ACTIVE_CONTEXT.get()
            if ctx is None:
                return await original(func, *args, **kwargs)
            return await _thread_call(ctx, pool, func, *args, **kwargs)

        to_thread._consensus_user_scanner_worker_hook = True
        asyncio.to_thread = to_thread


async def _run(meta: _Meta, query: str, ctx: Context) -> Finding:
    options = getattr(ctx, "options", None) or {}
    http = getattr(ctx, "http", None)
    if options.get("impersonate") is False or (http is not None and
                                               getattr(http, "impersonate_target", True) is None):
        return Finding.skipped(query, meta.kind, meta.name, meta.id,
                               "user-scanner cannot enforce disabled TLS impersonation", source=SOURCE)
    if options.get("extract") is False:
        return Finding.skipped(query, meta.kind, meta.name, meta.id,
                               "user-scanner cannot disable embedded profile extraction", source=SOURCE)
    if meta.loud and not getattr(ctx, "allow_loud", False):
        # Module.run() already filters loud modules; keep a guard here too because a
        # loud module can e-mail a real person (password reset) when called directly.
        return Finding.skipped(query, meta.kind, meta.name, meta.id, "loud module (use --allow-loud)",
                               source=SOURCE, category=meta.category, loud=True, nsfw=meta.nsfw)
    # A threading lock also covers callers on different event loops. Never block
    # the event loop while waiting, and cancellation before acquisition is safe.
    owns_context = False
    token = None
    context_token = None
    try:
        while not _enter_context(ctx):
            await asyncio.sleep(0.01)
        owns_context = True
        _install_httpx_hook()
        _install_worker_hook()
        token = _ACTIVE.set(True)
        context_token = _ACTIVE_CONTEXT.set(ctx)
        if meta.is_coroutine:
            raw = await meta.func(query)
        else:
            raw = await _thread_call(ctx, _executor(ctx), meta.func, query)
    except Exception as exc:  # noqa: BLE001 - third-party module code
        log.debug("user-scanner module %s raised", meta.id, exc_info=True)
        raw = _result_mod().Result.error(exc)
    finally:
        if context_token is not None:
            _ACTIVE_CONTEXT.reset(context_token)
        if token is not None:
            _ACTIVE.reset(token)
        if owns_context:
            _leave_context()
    return _to_finding(raw, query, meta)


def _executor(ctx: Context | None = None) -> concurrent.futures.ThreadPoolExecutor:
    """Shared pool for the blocking username modules (sized like upstream, not asyncio's default 32)."""
    global _EXECUTOR
    if _EXECUTOR is None:
        with _LOAD_LOCK:
            if _EXECUTOR is None:
                workers = DEFAULT_THREADS
                options = getattr(ctx, "options", None) or {}
                try:
                    workers = int(options.get("user_scanner_threads", workers))
                except (TypeError, ValueError, AttributeError):
                    pass
                _EXECUTOR = concurrent.futures.ThreadPoolExecutor(
                    max_workers=max(4, workers), thread_name_prefix="consensus-user-scanner"
                )
    return _EXECUTOR


def _timeout_of(ctx: Context) -> float | None:
    try:
        timeout = float(getattr(ctx, "timeout", None))
    except (TypeError, ValueError):
        return None
    return timeout if timeout > 0 else None


def _apply_context(ctx: Context) -> None:
    """Push ``ctx.timeout`` / ``ctx.proxy`` into user-scanner's globals - once per distinct setting."""
    global _applied
    key = (_timeout_of(ctx), getattr(ctx, "proxy", None) or None)
    if key == _applied:
        return
    with _SETTINGS_LOCK:
        if key == _applied:
            return
        helpers = _helpers()

        helpers.set_global_timeout(key[0])
        if key[1]:
            helpers.set_proxy_manager(proxies=[key[1]])
        else:
            helpers.set_proxy_manager()        # clear a proxy left behind by an earlier scan
        _applied = key


_HOOK_ATTR = "_consensus_user_scanner_hook"


def _install_httpx_hook() -> None:
    """Scoped version of upstream's httpx monkey-patch (see module docstring)."""
    global _hook_installed
    if _hook_installed:
        return
    with _SETTINGS_LOCK:
        if _hook_installed:
            return
        try:
            import httpx
        except Exception:  # pragma: no cover - httpx is a hard dependency
            _hook_installed = True
            return
        helpers = _helpers()

        def limited_timeouts(values, maximum):
            return {
                key: min(value, maximum)
                if type(value) in (int, float) and 0 <= value <= maximum
                else maximum
                for key, value in values.items()
            }

        def limit_request(client, request):
            ctx = _ACTIVE_CONTEXT.get()
            if not _ACTIVE.get() or ctx is None:
                return request
            maximum = _timeout_of(ctx)
            if maximum is None or not math.isfinite(maximum):
                return request
            values = client.timeout.as_dict()
            configured = request.extensions.get("timeout")
            if isinstance(configured, dict):
                values.update(configured)
            # HTTPX's public timeout request extension also covers direct send()
            # and explicit per-request overrides on clients created beforehand.
            # Keep the caller's request reusable outside this context, including
            # when send is cancelled or returns a response still being streamed.
            original_request = request
            request = copy.copy(request)
            # HTTPX's copy state intentionally omits its live body stream.
            request.stream = original_request.stream
            request.extensions = dict(original_request.extensions)
            request.extensions["timeout"] = limited_timeouts(values, maximum)
            return request

        def wrap_send(original):
            if inspect.iscoroutinefunction(original):
                @functools.wraps(original)
                async def send(self, request, *args, **kwargs):
                    request = limit_request(self, request)
                    return await original(self, request, *args, **kwargs)
            else:
                @functools.wraps(original)
                def send(self, request, *args, **kwargs):
                    request = limit_request(self, request)
                    return original(self, request, *args, **kwargs)
            setattr(send, _HOOK_ATTR, True)
            return send

        def _wrap(original):
            @functools.wraps(original)
            def __init__(self, *args, **kwargs):
                if _ACTIVE.get():
                    if not (kwargs.keys() & {"proxy", "proxies", "mounts", "transport"}):
                        proxy = helpers.get_proxy()
                        if proxy:
                            kwargs["proxy"] = proxy
                    timeout = helpers.get_global_timeout()
                    if timeout is not None:
                        configured = httpx.Timeout(kwargs.get("timeout", timeout)).as_dict()
                        kwargs["timeout"] = httpx.Timeout(**limited_timeouts(configured, timeout))
                original(self, *args, **kwargs)

            setattr(__init__, _HOOK_ATTR, True)
            return __init__

        for cls in (httpx.Client, httpx.AsyncClient):
            if not getattr(cls.__init__, _HOOK_ATTR, False):
                cls.__init__ = _wrap(cls.__init__)  # type: ignore[method-assign]
            if not getattr(cls.send, _HOOK_ATTR, False):
                cls.send = wrap_send(cls.send)
        _hook_installed = True


# ---------------------------------------------------------------------------
# Result -> Finding
# ---------------------------------------------------------------------------
_RATE_RE = re.compile(r"\b429\b|\brate\b|rate[\s_-]?limit|ratelimit|too many requests|throttl", re.I)
_BLOCK_RE = re.compile(
    r"\b40[13]\b|\bwaf\b|cloudflare|blocked|captcha|forbidden|access denied|bot[\s-]?protection"
    r"|datadome|akamai|perimeterx|incapsula|ddos-guard|\bprovider challenge\b",
    re.I,
)
_HTTP_RE = re.compile(r"(?:\bhttp\b|\bstatus(?:\s*code)?\b|\[)\s*[:=]?\s*([1-5]\d{2})\b", re.I)


def _coerce_result(raw: Any, result_cls: type) -> Any:
    if isinstance(raw, result_cls):
        return raw
    if raw is None:
        return result_cls.error("module returned no result")
    if isinstance(raw, int) and not isinstance(raw, bool):
        return result_cls.from_number(raw)
    if hasattr(raw, "status") and hasattr(raw, "get_reason"):   # Result from a second copy of the module
        return raw
    return result_cls.error(f"unexpected return type {type(raw).__name__}")


def _map_status(name: str | None, reason: str) -> Status:
    if name == "TAKEN":
        return Status.FOUND
    if name == "AVAILABLE":
        return Status.NOT_FOUND
    if name == "SKIPPED":
        return Status.SKIPPED
    if _RATE_RE.search(reason):
        return Status.RATE_LIMITED
    if _BLOCK_RE.search(reason):
        return Status.BLOCKED
    return Status.ERROR


def _http_status(reason: str) -> int | None:
    match = _HTTP_RE.search(reason)
    return int(match.group(1)) if match else None


def _to_finding(raw: Any, query: str, meta: _Meta) -> Finding:
    res = _coerce_result(raw, _result_mod().Result)
    try:
        reason = str(res.get_reason() or "").strip()
    except Exception as exc:  # noqa: BLE001
        reason = f"unreadable reason ({type(exc).__name__})"
    status = _map_status(getattr(res.status, "name", None), reason)

    extra: dict = {}
    try:
        extra.update(res.extra or {})
        if res.media:
            extra["media"] = dict(res.media)
    except Exception:  # noqa: BLE001
        pass

    error = None
    http_status = None
    if status.is_definitive:
        if reason:                      # e.g. "Username cannot contain periods"
            extra.setdefault("reason", reason)
    else:
        error = reason[:300] or None
        http_status = _http_status(reason)

    url = str(res.url).strip() if getattr(res, "url", None) else ""
    return Finding(
        query=query,
        query_type=meta.kind,
        site=meta.name,
        site_id=meta.id,
        status=status,
        url=url or None,
        category=meta.category,
        source=SOURCE,
        method=METHOD,
        extra=extra,
        error=error,
        http_status=http_status,
        loud=meta.loud,
        nsfw=meta.nsfw,
    )
