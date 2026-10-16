"""socialscan adapter - exact username / e-mail availability via sign-up APIs.

Wraps the platform classes vendored under :mod:`consensus_osint.vendor.socialscan`
(MPL-2.0, https://github.com/iojw/socialscan) as Consensus :class:`Module`
objects.  socialscan asks each platform's own sign-up *validation* endpoint
whether an identifier is still available. The shipped policy holds variants
whose responses cannot establish account presence (for example, reserved names).
These validation flows are classified quiet (``loud=False``); this is a reviewed
interaction classification, not a guarantee about future provider behavior.

Two modules are produced per platform where upstream supports both queries:
``socialscan-<platform>-username`` (kind ``username``) and
``socialscan-<platform>-email`` (kind ``email``).

socialscan is built on ``aiohttp`` (Consensus itself uses httpx), so each check
opens its own short-lived ``aiohttp.ClientSession`` configured from the scan
:class:`Context` (timeout, proxy).  That session doubles as the cookie jar the
token "pre-request" of several platforms relies on, which is why it is created
per check rather than shared.  socialscan forces its own ``User-Agent`` on
every request (``BasePlatform.DEFAULT_HEADERS``), so ``Context.user_agent``
is not applied here.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import aiohttp

from consensus_osint.core.models import Finding, Status
from consensus_osint.core.modules import Context, Module
from consensus_osint.vendor.socialscan import platforms as sp

log = logging.getLogger("consensus.adapters.socialscan")

SOURCE = "socialscan"
METHOD = "signup api (socialscan)"

#: upstream class name -> (slug, display name, category, main URL), in display
#: order.  Classes absent from the vendored copy (Spotify was dropped upstream)
#: are skipped; classes upstream adds later are picked up with default metadata.
CATALOG: list[tuple[str, str, str, str, str]] = [
    ("Snapchat", "snapchat", "Snapchat", "social", "https://www.snapchat.com"),
    ("Instagram", "instagram", "Instagram", "social", "https://www.instagram.com"),
    ("GitHub", "github", "GitHub", "coding", "https://github.com"),
    ("Tumblr", "tumblr", "Tumblr", "social", "https://www.tumblr.com"),
    ("GitLab", "gitlab", "GitLab", "coding", "https://gitlab.com"),
    ("Reddit", "reddit", "Reddit", "social", "https://www.reddit.com"),
    ("Twitter", "twitter", "Twitter", "social", "https://twitter.com"),
    ("Lastfm", "lastfm", "Last.fm", "social", "https://www.last.fm"),
    ("Pinterest", "pinterest", "Pinterest", "social", "https://www.pinterest.com"),
    ("Spotify", "spotify", "Spotify", "music", "https://www.spotify.com"),
    ("Yahoo", "yahoo", "Yahoo", "mail", "https://www.yahoo.com"),
    ("Firefox", "firefox", "Firefox Accounts", "tech", "https://accounts.firefox.com"),
]

#: Explicit throttling messages; missing tokens, content-type changes, bare
#: numbers and generic access denial do not establish rate limiting.
_RATE_LIMIT_MARKERS = ("too many requests", "excessive requests", "rate limit", "http 429")
_BLOCKED_STATUSES = {401, 403, 406, 407, 418, 451}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _new_session(timeout: aiohttp.ClientTimeout) -> aiohttp.ClientSession:
    """Create a Socialscan session."""
    import aiohttp

    return aiohttp.ClientSession(timeout=timeout)


def _looks_rate_limited(message: str | None) -> bool:
    low = (message or "").lower()
    return any(marker in low for marker in _RATE_LIMIT_MARKERS)


def response_to_finding(resp: sp.PlatformResponse, *, query: str, kind: str, site: str,
                        site_id: str, category: str, url_main: str | None) -> Finding:
    """Translate a socialscan ``PlatformResponse`` into a :class:`Finding`.

    ======================================  ===========================================
    ``success and valid and not available``  FOUND - an account owns the identifier
    ``success and available``                NOT_FOUND
    ``success and not valid``                SKIPPED - the platform rejects the form
                                             of the identifier (error = its message)
    ``not success``                          ERROR, or RATE_LIMITED when the message
                                             says the platform throttled us
    ======================================  ===========================================
    """
    message = (resp.message or "").strip()
    base = dict(
        query=query, query_type=kind, site=site, site_id=site_id, category=category,
        source=SOURCE, method=METHOD,
        extra={"message": message, "available": bool(resp.available),
               "valid": bool(resp.valid), "success": bool(resp.success)},
    )
    if resp.success and resp.valid and not resp.available:
        return Finding(status=Status.FOUND, url=resp.link or url_main, **base)
    if resp.success and resp.available:
        return Finding(status=Status.NOT_FOUND, url=url_main, **base)
    if resp.success:  # and not valid
        base["extra"]["reason"] = "invalid"
        return Finding(status=Status.SKIPPED, url=url_main, error=message or "invalid", **base)
    status = Status.RATE_LIMITED if _looks_rate_limited(message) else Status.ERROR
    return Finding(status=status, url=url_main, error=message or "failure", **base)


def _failure(query: str, kind: str, site: str, site_id: str, category: str,
             url_main: str | None, message: str, http_status: int | None = None, *, blocked=False) -> Finding:
    if http_status == 429:
        status = Status.RATE_LIMITED
    elif blocked or http_status in _BLOCKED_STATUSES:
        status = Status.BLOCKED
    elif http_status is not None and http_status >= 400:
        status = Status.ERROR
    else:
        status = Status.RATE_LIMITED if _looks_rate_limited(message) else Status.ERROR
    return Finding(query=query, query_type=kind, site=site, site_id=site_id, status=status,
                   url=url_main, category=category, source=SOURCE, method=METHOD,
                   error=message[:300], http_status=http_status)


def _make_check(cls: type, kind: str, site: str, site_id: str, category: str,
                url_main: str | None) -> Callable[[str, Context], Awaitable[Finding]]:
    async def check(query: str, ctx: Context) -> Finding:
        import aiohttp

        total = float(ctx.timeout or sp.BasePlatform.TIMEOUT_DURATION)
        timeout = aiohttp.ClientTimeout(total=total,
                                        connect=min(total, sp.BasePlatform.TIMEOUT_DURATION))
        proxy_list = [ctx.proxy] if ctx.proxy else []
        checker = None
        try:
            async with _new_session(timeout) as session:
                checker = cls(session, proxy_list=proxy_list)
                # BasePlatform._request passes ``self.client_timeout`` on every
                # request, which would override the session default - shadow it.
                checker.client_timeout = timeout
                if kind == "email":
                    resp = await checker.check_email(query)
                else:
                    resp = await checker.check_username(query)
                if resp is None:  # upstream returns None on unhandled branches
                    raise sp.QueryError("Error retrieving result")
        except (asyncio.TimeoutError, TimeoutError):
            return _failure(query, kind, site, site_id, category, url_main,
                            f"timed out after {total:g}s")
        except Exception as exc:  # noqa: BLE001 - aiohttp.ClientError, KeyError, QueryError, ...
            log.debug("socialscan %s failed for %r", site_id, query, exc_info=True)
            return _failure(query, kind, site, site_id, category, url_main,
                            f"{type(exc).__name__} - {exc}",
                            http_status=getattr(exc, "http_status", None) or getattr(checker, "last_http_status", None),
                            blocked=getattr(exc, "blocked", False) is True)
        finding = response_to_finding(resp, query=query, kind=kind, site=site, site_id=site_id,
                                      category=category, url_main=url_main)
        finding.http_status = getattr(checker, "last_http_status", None)
        return finding

    check.__name__ = "check_" + site_id.replace("-", "_")
    return check


def _modules_for(cls: type, slug: str, site: str, category: str,
                 url_main: str | None) -> list[Module]:
    try:
        sp.Platforms(cls)  # response helpers need the class to be an enum member
    except ValueError:
        log.warning("socialscan platform %s is not a Platforms member; skipped", cls.__name__)
        return []
    out: list[Module] = []
    for kind, mixin in (("username", sp.UsernameQueryable), ("email", sp.EmailQueryable)):
        if not issubclass(cls, mixin):
            continue
        site_id = f"socialscan-{slug}-{kind}"
        out.append(Module(
            id=site_id, name=site, kind=kind,
            check=_make_check(cls, kind, site, site_id, category, url_main),
            category=category, source=SOURCE, url_main=url_main, loud=False,
            tags=["socialscan", "signup-api"], method=METHOD,
        ))
    return out


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def load_modules() -> list[Module]:
    """Return one Module per (platform, kind) pair supported by vendored socialscan."""
    modules: list[Module] = []
    seen: set = set()
    for class_name, slug, site, category, url_main in CATALOG:
        cls = getattr(sp, class_name, None)
        if cls is None:
            continue
        seen.add(cls)
        modules.extend(_modules_for(cls, slug, site, category, url_main))
    # platform classes the catalogue does not know yet (future upstream syncs)
    for name in dir(sp):
        obj = getattr(sp, name)
        if (isinstance(obj, type) and issubclass(obj, sp.BasePlatform)
                and obj is not sp.BasePlatform and obj not in seen):
            seen.add(obj)
            modules.extend(_modules_for(obj, name.lower(), name, "misc", getattr(obj, "URL", None)))
    return modules


__all__ = ["load_modules", "response_to_finding", "CATALOG", "SOURCE", "METHOD"]
