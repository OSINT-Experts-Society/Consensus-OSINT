import asyncio
import logging
import math
import threading
from typing import Callable, Literal, Optional

from curl_cffi import requests as cffi

from consensus_osint.vendor.user_scanner.core.helpers import get_global_timeout, get_proxy
from consensus_osint.vendor.user_scanner.core.result import Result

DEFAULT_IMPERSONATE = "chrome"
DEFAULT_TIMEOUT = 15.0

_sessions: dict[tuple, cffi.Session] = {}
_key_locks: dict[tuple, threading.Lock] = {}
_warmed: set[tuple] = set()
_lock = threading.Lock()


def close_cached_transports() -> None:
    """Close all thread-local curl handles after the adapter's workers drain."""
    with _lock:
        sessions = list(_sessions.values())
        _sessions.clear()
        _key_locks.clear()
        _warmed.clear()
    for session in sessions:
        # Session.close() only closes the calling thread's handle. Handles used
        # by other pool threads must also be released, without waiting for GC.
        for resource in (session, *session._consensus_handles):
            try:
                resource.close()
            except Exception:
                logging.getLogger(__name__).warning("Could not close cached curl resource", exc_info=True)
        session._consensus_handles.clear()


def impersonate_validate(
    url: str,
    func: Callable[[cffi.Response], Result],
    warmup_url: Optional[str] = None,
    impersonate: str = DEFAULT_IMPERSONATE,
    show_url: Optional[str] = None,
    **kwargs,
) -> Result:
    """Like ``generic_validate`` using the retained curl_cffi transport.

    Each explicit ``warmup_url`` is requested once per cached session. This
    preserves the provider's prerequisite flow; a completed request does not
    establish successful access or challenge resolution. The provider parser
    must still distinguish the lookup response from a challenge or failure.
    """
    display_url = show_url or url
    try:
        response = impersonate_request(
            url, warmup_url=warmup_url, impersonate=impersonate, **kwargs
        )
        return func(response).update(url=display_url)
    except Exception as e:
        return Result.error(e, url=display_url)


def impersonate_request(
    url: str,
    method: Literal["GET", "POST"] = "GET",
    warmup_url: Optional[str] = None,
    impersonate: str = DEFAULT_IMPERSONATE,
    **kwargs,
) -> cffi.Response:
    """Issue a single request through a warmed, cookie-persistent browser-
    impersonating session and return the raw response. Reuses the same cached
    session as ``impersonate_validate`` for a given (impersonate, proxy), so a
    follow-up call keeps the session's provider-scoped cookies.
    """
    session = _get_warm_session(impersonate, get_proxy(), warmup_url)
    kwargs.setdefault("timeout", _timeout())
    maximum = get_global_timeout()
    if maximum is not None:
        kwargs["timeout"] = _limit_timeout(kwargs["timeout"], maximum)
    kwargs.setdefault("allow_redirects", False)
    return session.request(method, url, **kwargs)


async def impersonate_request_async(
    url: str,
    method: Literal["GET", "POST"] = "GET",
    warmup_url: Optional[str] = None,
    impersonate: str = DEFAULT_IMPERSONATE,
    **kwargs,
) -> cffi.Response:
    """``impersonate_request`` for the async email modules. curl_cffi's session
    API is blocking, so it runs in a worker thread; the session cache is shared
    with the synchronous username modules, so cookies carry over either way.
    """
    return await asyncio.to_thread(
        impersonate_request,
        url,
        method,
        warmup_url=warmup_url,
        impersonate=impersonate,
        **kwargs,
    )


def _get_warm_session(
    impersonate: str, proxy: Optional[str], warmup_url: Optional[str]
) -> cffi.Session:
    key = (impersonate, proxy)
    with _lock:
        session = _sessions.get(key)
        if session is None:
            session = cffi.Session(
                # curl_cffi types this as a browser-name Literal; the value is a
                # validated runtime string, so widen it here only.
                impersonate=impersonate,  # type: ignore[arg-type]
                proxies={"http": proxy, "https": proxy} if proxy else None,
            )
            session._consensus_handles = set()
            _sessions[key] = session
            _key_locks[key] = threading.Lock()
            
        key_lock = _key_locks.get(key)
        if key_lock is None:
            key_lock = threading.Lock()
            _key_locks[key] = key_lock

        session._consensus_handles.add(session.curl)

    warmup_key = (key, warmup_url)
    if warmup_url and warmup_key not in _warmed:
        with key_lock:
            if warmup_key not in _warmed:
                # Record an attempted prerequisite, not a successful challenge.
                # Keep the existing single request and no automatic retry.
                session.get(warmup_url, timeout=_timeout())
                _warmed.add(warmup_key)

    return session


def _limit_timeout(value, maximum):
    # curl treats scalar zero/None as unlimited, unlike HTTPX's zero timeout.
    # A (connect, read) pair gives curl a total of their sum. Preserve a shorter
    # pair; scale a longer one without increasing either phase's limit.
    if isinstance(value, tuple) and len(value) == 2:
        if all(type(part) in (int, float) and math.isfinite(part) and part >= 0 for part in value):
            total = sum(value)
            if total > 0:
                scale = min(1.0, maximum / total)
                return tuple(part * scale for part in value)
        return maximum
    return value if type(value) in (int, float) and 0 < value <= maximum else maximum


def _timeout() -> float:
    # Honour the CLI -t flag (get_global_timeout), matching make_request();
    # fall back to DEFAULT_TIMEOUT when the user has not set one.
    global_timeout = get_global_timeout()
    return global_timeout if global_timeout is not None else DEFAULT_TIMEOUT
