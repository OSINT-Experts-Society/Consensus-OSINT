"""numint adapter - "is this phone number registered here?" presence checks.

Wraps the presence checks vendored under :mod:`consensus_osint.vendor.numint`
(MIT, https://github.com/whoamitang/numint; Amazon, Instagram and Snapchat are
numint's ports of megadose/ignorant) as Consensus phone :class:`Module` objects,
one per site: ``numint-amazon``, ``numint-instagram``, ``numint-microsoft``,
``numint-snapchat`` and ``numint-twitter``.

Each check reads a site's own sign-up / sign-in / recovery-lookup response to
decide whether the number is linked to an account and captures any masked
identifier the site leaks (surfaced in ``finding.extra``).  Nothing is
submitted that completes a sign-up or a reset.  Amazon is the one to flag:
its check posts the number into the live sign-in form and Amazon can answer a
phone-number sign-in with an OTP challenge, so that module is ``loud``.

numint's engine is not vendored; this adapter reproduces the relevant part of
``Engine._run_presence`` (a ``follow_redirects`` httpx client with the scan
timeout) and adds proxy support plus finer failure classification.  Queries
arrive as E.164 strings (``"+14155552671"``) and are parsed with the vendored
``core/parser.py`` into the ``ParsedNumber`` the checks expect.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

from consensus_osint.core.models import Finding, Status
from consensus_osint.core.modules import Context, Module
from consensus_osint.vendor.numint.core.models import PresenceResult
from consensus_osint.vendor.numint.presence import discover_presence
from consensus_osint.vendor.numint.presence.base import CHROME_UAS

log = logging.getLogger("consensus.adapters.numint")

SOURCE = "numint"
KIND = "phone"


@dataclass(frozen=True)
class SiteInfo:
    slug: str
    name: str
    category: str
    url: str | None
    loud: bool = False
    loud_reason: str = ""


#: upstream ``PresenceCheck.site`` -> Consensus metadata.
SITE_INFO: dict[str, SiteInfo] = {
    "amazon": SiteInfo(
        "amazon", "Amazon", "shopping", "https://www.amazon.com", loud=True,
        loud_reason=(
            "posts the number as the identifier of Amazon's live /ap/signin form; Amazon "
            "may answer a phone-number sign-in with an OTP challenge (passwordless / OTP "
            "sign-in flows), so the target could receive an SMS"),
    ),
    "instagram": SiteInfo("instagram", "Instagram", "social", "https://www.instagram.com"),
    "microsoft": SiteInfo("microsoft", "Microsoft account", "tech", "https://login.live.com"),
    "snapchat": SiteInfo("snapchat", "Snapchat", "social", "https://www.snapchat.com"),
    "twitter/x": SiteInfo("twitter", "Twitter / X", "social", "https://twitter.com"),
}

_BLOCKED_STATUSES = {401, 403, 406, 407, 418, 451}


def _default_info(site: str) -> SiteInfo:
    slug = re.sub(r"[^a-z0-9]+", "-", site.lower()).strip("-") or "site"
    return SiteInfo(slug, site.title(), "social", None)


# ---------------------------------------------------------------------------
# transport bookkeeping
# ---------------------------------------------------------------------------
class _RecordingStream(httpx.AsyncByteStream):
    def __init__(self, inner, record_error):
        self.inner = inner
        self.record_error = record_error

    async def __aiter__(self):
        try:
            async for chunk in self.inner:
                yield chunk
        except Exception as exc:
            self.record_error(exc)
            raise

    async def aclose(self):
        try:
            await self.inner.aclose()
        except Exception as exc:
            self.record_error(exc)
            raise


class _RecordingTransport(httpx.AsyncBaseTransport):
    """Delegating transport that remembers the outcome of the last request.

    Some retained numint checks catch failures and report
    ``registered="rate_limited"``. Recording what the
    transport actually saw lets the adapter tell a dead network (ERROR) from a
    real HTTP 429 (RATE_LIMITED) or a 401/403 (BLOCKED). HTTP failures stop before
    provider parsing or later requests. Unrecognized successful responses do not
    establish rate limiting.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner
        self.last_status: int | None = None
        self.last_error: str | None = None
        self.last_event: str | None = None  # "response" | "error"
        self.requests = 0

    def _record_error(self, exc):
        self.last_status = None
        self.last_error = f"{type(exc).__name__}: {exc}".rstrip(": ")
        self.last_event = "error"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        try:
            response = await self._inner.handle_async_request(request)
        except Exception as exc:  # noqa: BLE001 - recorded, then re-raised for the check
            self._record_error(exc)
            raise
        self.last_status = response.status_code
        self.last_event = "response"
        self.last_error = None
        if response.status_code >= 400:
            await response.aclose()
            raise httpx.HTTPStatusError(f"HTTP {response.status_code}", request=request, response=response)
        response.stream = _RecordingStream(response.stream, self._record_error)
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


def _make_transport(ctx: Context) -> _RecordingTransport:
    """Create the HTTP transport."""
    return _RecordingTransport(httpx.AsyncHTTPTransport(proxy=ctx.proxy or None))


# ---------------------------------------------------------------------------
# result mapping
# ---------------------------------------------------------------------------
def result_to_finding(result: PresenceResult, *, query: str, site: str, site_id: str,
                      category: str, url_main: str | None, method: str | None = None,
                      transport: _RecordingTransport | None = None) -> Finding:
    """Map a numint ``PresenceResult`` onto a :class:`Finding`.

    ``registered``: ``yes`` -> FOUND, ``no`` -> NOT_FOUND, ``unknown`` -> UNKNOWN
    (or SKIPPED when the check declined the number, e.g. an unsupported country
    code), ``rate_limited`` -> UNKNOWN unless transport evidence establishes
    RATE_LIMITED / BLOCKED / ERROR, ``error`` -> ERROR (RATE_LIMITED / BLOCKED
    when the text says so). Transport failures take precedence over every
    provider verdict. Masked e-mail / phone hints and the username fragment go to
    ``extra``.
    """
    extra: dict = {"registered": result.registered, "flow": result.method}
    for key in ("masked_email", "masked_phone", "hint"):
        value = getattr(result, key, None)
        if value:
            extra[key] = value
    if result.elapsed_ms is not None:
        extra["upstream_elapsed_ms"] = result.elapsed_ms

    last_status = getattr(transport, "last_status", None)
    last_event = getattr(transport, "last_event", None)
    last_error = getattr(transport, "last_error", None)
    base = dict(query=query, query_type=KIND, site=site, site_id=site_id, category=category,
                source=SOURCE, method=method, url=url_main, extra=extra, http_status=last_status)

    verdict = (result.registered or "unknown").lower()
    err = (result.error or "").strip()
    if last_event == "error":
        return Finding(status=Status.ERROR, error=(last_error or err or "network error")[:300], **base)
    if last_status == 429:
        return Finding(status=Status.RATE_LIMITED, error="HTTP 429", **base)
    if last_status in _BLOCKED_STATUSES:
        return Finding(status=Status.BLOCKED, error=f"HTTP {last_status}", **base)
    if last_status is not None and last_status >= 400:
        return Finding(status=Status.ERROR, error=f"HTTP {last_status}", **base)
    if verdict == "yes":
        return Finding(status=Status.FOUND, **base)
    if verdict == "no":
        return Finding(status=Status.NOT_FOUND, **base)
    if verdict == "rate_limited":
        return Finding(status=Status.UNKNOWN,
                       error=err or "Provider response was not recognized; rate limiting was not confirmed.", **base)
    if verdict == "unknown":
        if "not supported" in err.lower():
            return Finding(status=Status.SKIPPED, error=err, **base)
        return Finding(status=Status.UNKNOWN, error=err or None, **base)
    if verdict == "error":
        low = err.lower()
        if "429" in low or "rate limit" in low or "too many" in low:
            return Finding(status=Status.RATE_LIMITED, error=err, **base)
        if "captcha" in low or "403" in low or "blocked" in low or "forbidden" in low:
            return Finding(status=Status.BLOCKED, error=err, **base)
        return Finding(status=Status.ERROR, error=(err or "error")[:300], **base)
    return Finding(status=Status.ERROR, error=f"unrecognised presence verdict {verdict!r}", **base)


# ---------------------------------------------------------------------------
# module construction
# ---------------------------------------------------------------------------
def _make_check(check_cls: type, info: SiteInfo, site_id: str,
                method: str) -> Callable[[str, Context], Awaitable[Finding]]:
    async def check(query: str, ctx: Context) -> Finding:
        try:
            from ..core.phone import parse_number as describe_number
            from ..vendor.numint.core.parser import parse_number

            parsed_info = describe_number(query)
            if not parsed_info.get("valid"):
                raise ValueError(parsed_info.get("error") or "invalid number")
            if not parsed_info.get("online_allowed"):
                return Finding.skipped(query, KIND, info.name, site_id,
                                       "phone checks require a valid number with an explicit country code",
                                       source=SOURCE, category=info.category, url=info.url)
            number = parse_number(parsed_info["e164"])
        except Exception as exc:  # noqa: BLE001 - ParseError or anything phonenumbers raises
            return Finding.skipped(query, KIND, info.name, site_id,
                                   f"unparseable phone number: {exc}"[:300],
                                   source=SOURCE, category=info.category, url=info.url)
        headers = {"User-Agent": ctx.user_agent or CHROME_UAS[0]}
        try:
            transport = _make_transport(ctx)
            async with httpx.AsyncClient(timeout=ctx.timeout, headers=headers,
                                         follow_redirects=True, transport=transport) as client:
                # PresenceCheck.check never raises: upstream turns failures into error rows
                result = await check_cls().check(number, client)
        except Exception as exc:  # noqa: BLE001 - client / proxy setup problems
            log.debug("numint %s failed for %r", site_id, query, exc_info=True)
            return Finding.error_result(query, KIND, info.name, site_id, f"{type(exc).__name__}: {exc}",
                                        source=SOURCE, category=info.category, url=info.url)
        finding = result_to_finding(result, query=query, site=info.name, site_id=site_id,
                                    category=info.category, url_main=info.url, method=method,
                                    transport=transport)
        finding.extra.setdefault("e164", number.e164)
        return finding

    check.__name__ = "check_" + site_id.replace("-", "_")
    return check


def load_modules() -> list[Module]:
    """Return one phone Module per registered numint presence check."""
    modules: list[Module] = []
    used_ids: set = set()
    for cls in discover_presence():
        site_key = str(getattr(cls, "site", cls.__name__)).lower()
        info = SITE_INFO.get(site_key) or _default_info(site_key)
        site_id = f"numint-{info.slug}"
        if site_id in used_ids:  # two checks for one site - keep both, keep ids unique
            site_id = f"{site_id}-{cls.__name__.lower()}"
        used_ids.add(site_id)
        # upstream's own flag wins when it says the endpoint can notify the target
        loud = info.loud or not getattr(cls, "non_notifying", True)
        method = f"{getattr(cls, 'method', 'lookup')} flow (numint)"
        tags = ["numint", "presence"]
        if loud and info.loud_reason:
            tags.append("otp-risk")
        modules.append(Module(
            id=site_id, name=info.name, kind=KIND,
            check=_make_check(cls, info, site_id, method),
            category=info.category, source=SOURCE, url_main=info.url, loud=loud,
            tags=tags, method=method,
        ))
    return modules


__all__ = ["load_modules", "result_to_finding", "SITE_INFO", "SiteInfo", "SOURCE", "KIND"]
