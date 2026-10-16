"""Plugin interface for *code* modules (as opposed to data-driven site entries).

Upstream projects ship hundreds of hand-written checks (holehe email modules,
user-scanner username/email modules, socialscan platforms, ignorant/numint phone
modules ...).  Each family is vendored under ``consensus_osint.vendor`` and wrapped
by an *adapter* that exposes objects implementing :class:`Module`.

A module is a small object with metadata plus an ``async check(query, ctx)``
coroutine returning a :class:`~consensus_osint.core.models.Finding`.
"""
from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .models import Finding, QueryType, Status

log = logging.getLogger("consensus.modules")


@dataclass
class Context:
    """Per-scan shared state handed to every module.

    ``client`` is an httpx.AsyncClient (see core.http).  ``impersonate`` is a
    curl_cffi based request helper for TLS-fingerprint protected sites, or
    None when curl_cffi is unavailable.
    """

    client: object
    timeout: float = 15.0
    proxy: str | None = None
    http: object = None                         # Consensus's own Http wrapper (impersonation, per-host limits)
    allow_loud: bool = False
    user_agent: str | None = None
    impersonate: Callable | None = None
    options: dict = field(default_factory=dict)


@dataclass
class Module:
    """A single code-driven check."""

    id: str
    name: str
    kind: str                                   # "username" | "email" | "phone"
    check: Callable[[str, Context], Awaitable[Finding]]
    category: str = "misc"
    source: str = "module"                      # upstream family: holehe, user-scanner, socialscan, ignorant, numint ...
    url_main: str | None = None
    loud: bool = False                          # may send a notification / password-reset e-mail to the target
    nsfw: bool = False
    tags: list = field(default_factory=list)
    method: str | None = None                # human readable technique
    disabled_reason: str | None = None
    replaces: str | None = None
    unsupported_proxy: str | None = None

    def __post_init__(self) -> None:
        from .module_policy import restriction_for

        policy = restriction_for(self.id, self.replaces)
        self.disabled_reason = self.disabled_reason or policy.disabled_reason
        self.loud = self.loud or policy.require_loud
        self.unsupported_proxy = self.unsupported_proxy or policy.unsupported_proxy
        original = self.check

        @functools.wraps(original)
        async def guarded(query: str, ctx: Context) -> Finding:
            reason = self.disabled_reason
            if not reason and self.unsupported_proxy and ctx.proxy:
                reason = self.unsupported_proxy
            if not reason and self.loud and not ctx.allow_loud:
                reason = "loud module (use --allow-loud)"
            if reason:
                return Finding.skipped(query, self.kind, self.name, self.id, reason,
                                       source=self.source, category=self.category, loud=self.loud,
                                       nsfw=self.nsfw, url=self.url_main)
            finding = await original(query, ctx)
            if isinstance(finding, Finding):
                finding.loud = finding.loud or self.loud
                finding.nsfw = finding.nsfw or self.nsfw
            return finding

        # Adapters expose check() directly as well as run(); both must enforce
        # the reviewed restrictions before executing any third-party code.
        self.check = guarded

    async def run(self, query: str, ctx: Context) -> Finding:
        """Run the check with timeout protection and exception normalisation."""
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        try:
            finding = await asyncio.wait_for(self.check(query, ctx), timeout=ctx.timeout + 10)
            if not isinstance(finding, Finding):
                raise TypeError("module must return a Finding")
        except asyncio.TimeoutError:
            finding = Finding.error_result(query, self.kind, self.name, self.id, "module timed out",
                                           source=self.source, category=self.category, url=self.url_main)
        except Exception as exc:  # noqa: BLE001 - modules are third-party code
            log.debug("module %s raised", self.id, exc_info=True)
            finding = Finding.error_result(query, self.kind, self.name, self.id, f"{type(exc).__name__}: {exc}",
                                           source=self.source, category=self.category, url=self.url_main)
        finding.elapsed = round(loop.time() - t0, 3)
        finding.loud = finding.loud or self.loud
        finding.nsfw = finding.nsfw or self.nsfw
        if not finding.tags:
            finding.tags = list(self.tags)
        if finding.status is Status.FOUND and finding.confidence is None:
            try:
                from .confidence import base_confidence

                finding.confidence = base_confidence(finding)
            except Exception:  # noqa: BLE001
                pass
        return finding


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------
ADAPTERS = {
    # family -> import path of a function ``load_modules() -> list[Module]``
    "user-scanner": "consensus_osint.adapters.user_scanner_adapter:load_modules",
    "holehe": "consensus_osint.adapters.holehe_adapter:load_modules",
    "socialscan": "consensus_osint.adapters.socialscan_adapter:load_modules",
    "ignorant": "consensus_osint.adapters.ignorant_adapter:load_modules",
    "numint": "consensus_osint.adapters.numint_adapter:load_modules",
    "rules": "consensus_osint.adapters.rules_adapter:load_modules",
    "extras": "consensus_osint.adapters.extras_adapter:load_modules",
}

# A family whose top-level dependency (from the optional [modules] extra) is absent is
# skipped cleanly with a single hint, rather than logging one failure per site module.
FAMILY_REQUIRES = {
    "user-scanner": "curl_cffi",
    "holehe": "trio",
    "ignorant": "trio",
    "socialscan": "aiohttp",
}

_cache: dict[str, list] = {}
_hinted = False


def _hint_modules_extra() -> None:
    global _hinted
    if not _hinted:
        log.warning('some code-module families need the optional extra — run:  pip install "consensus-osint[modules]"')
        _hinted = True


def load_family(family: str) -> list:
    """Import and cache all modules of one adapter family (never raises)."""
    if family in _cache:
        return _cache[family]
    import importlib.util

    req = FAMILY_REQUIRES.get(family)
    if req and importlib.util.find_spec(req) is None:
        _hint_modules_extra()
        _cache[family] = []
        return []
    path = ADAPTERS.get(family)
    if not path:
        _cache[family] = []
        return []
    mod_name, func_name = path.split(":")
    try:
        mod = importlib.import_module(mod_name)
        modules = list(getattr(mod, func_name)())
    except Exception as exc:  # noqa: BLE001
        log.warning("adapter %s failed to load: %s", family, exc)
        log.debug("adapter failure", exc_info=True)
        modules = []
    _cache[family] = modules
    return modules


def all_modules(kind: str | None = None, families: list | None = None) -> list:
    """Return every registered module, optionally filtered by kind and family."""
    out: list = []
    for fam in (families or list(ADAPTERS)):
        for m in load_family(fam):
            if kind is None or m.kind == kind:
                out.append(m)
    # stable, de-duplicated by id
    seen = set()
    uniq = []
    for m in out:
        if m.id in seen:
            continue
        seen.add(m.id)
        uniq.append(m)
    return uniq


#: When several families check the same service for the same kind of identifier,
#: the family listed first is kept and the rest are skipped, so one scan sends one
#: request per service.  Ordered by track record; ``--all-modules`` runs them all.
FAMILY_PRECEDENCE = ("socialscan", "holehe", "ignorant", "rules", "user-scanner", "extras", "numint")


@functools.lru_cache(maxsize=16384)
def _service_host(url: str | None) -> str:
    import re
    from urllib.parse import urlparse

    if not url:
        return ""
    try:
        host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        return ""
    return re.sub(r"^(www|m|mobile)\.", "", host)


_SHARED_API_HOSTS = frozenset({"googleapis.com", "identitytoolkit.googleapis.com"})
_APP_STORE_HOST = "play.google.com"


@functools.lru_cache(maxsize=16384)
def _service_key(url: str | None) -> str:
    """Known provider/app identity; an unresolved shared host has no identity."""
    import re
    from urllib.parse import parse_qs, urlsplit

    host = _service_host(url)
    if host in _SHARED_API_HOSTS:
        return ""
    if host != _APP_STORE_HOST:
        return host
    try:
        parsed = urlsplit(url if "://" in url else "https://" + url)
        values = parse_qs(parsed.query, max_num_fields=64).get("id", [])
        if (parsed.path.rstrip("/") == "/store/apps/details" and len(values) == 1
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", values[0])):
            return "app:play.google.com:" + values[0]
    except ValueError:
        pass
    return ""


def _site_service_key(site) -> str:
    base = getattr(site, "domain", None) or getattr(site, "url_main", None) or getattr(site, "url", None)
    if _service_host(base) == _APP_STORE_HOST:
        return _service_key(getattr(site, "url", None)) or _service_key(getattr(site, "url_main", None))
    return _service_key(base)


def finding_service_key(finding, *, fallback: str) -> str | None:
    """Prefer the scan-time identity; unknown shared hosts cannot corroborate."""
    recorded = finding.extra.get("_service_identity")
    if isinstance(recorded, str) and recorded:
        return recorded
    recorded = finding.extra.get("_service_host")
    url = recorded if isinstance(recorded, str) and recorded else finding.url
    host = _service_host(url)
    identity = _service_key(url)
    if identity:
        return identity
    if host in _SHARED_API_HOSTS or host == _APP_STORE_HOST:
        return None
    return fallback


def dedupe_modules(modules: list) -> tuple:
    """Keep one module per (kind, service) so a scan never asks a service twice.

    Two vendored families frequently carry the same check - numint's phone probes
    are derived from ignorant's, and holehe, the e-mail-site rules and the extras
    all hit Duolingo's one lookup endpoint - which meant the same request going out
    two or three times per scan.  Returns ``(kept, skipped)``; modules that do not
    declare a service URL cannot be grouped and are always kept.
    """
    rank = {f: i for i, f in enumerate(FAMILY_PRECEDENCE)}
    def priority(module):
        return (bool(getattr(module, "disabled_reason", None)), getattr(module, "loud", False),
                rank.get(module.source, len(rank)))

    # Known app identities can share a hosting domain. Unresolved shared API
    # hosts are kept separately instead of guessing they are one provider.
    best: dict = {}
    for m in modules:
        host = _service_key(m.url_main)
        if not host:
            continue
        key = (m.kind, host)
        cur = best.get(key)
        if cur is None or priority(m) < priority(cur):
            best[key] = m
    keep_ids = {id(m) for m in best.values()}
    kept, skipped = [], []
    for m in modules:
        (kept if not _service_key(m.url_main) or id(m) in keep_ids else skipped).append(m)
    return kept, skipped


def reconcile_plan(sites: list, modules: list, *, ctx: Context | None = None, query: str | None = None) -> tuple:
    """One request per service across BOTH the site database and the code modules.

    The site database and the code families overlap heavily (a default username
    scan used to ask about 180 services twice).  For each service a code module
    also covers: a site rule with real markers keeps it; a status-only site rule
    yields to the module, whose verdict logic is explicit. Maintained Discourse
    and selected HTML profile contracts preserve fields over equivalent catalogue
    routes. Scan options retain catalogue fallbacks for unavailable code adapters. Returns
    ``(sites, modules, paired)`` where ``paired`` lists ``(kept_id, skipped_id)``.
    """
    from .discourse_contracts import prefer_profile_module
    from .profile_page_contracts import prefer_profile_module as prefer_page_module
    from .profile_page_contracts import profile_alias_sites
    from .selected_profile_guards import same_selected_profile

    by_host: dict = {}  # Provider/app keys, not necessarily bare hostnames.
    eligible_sites = []
    for s in sites:
        if getattr(s, "disabled", False) or getattr(s, "audit_disabled_reason", None):
            continue
        eligible_sites.append(s)
        host = _site_service_key(s)
        if host:
            by_host.setdefault(host, []).append(s)
    drop_sites: set = set()
    kept_modules: list = []
    paired: list = []
    for m in modules:
        if getattr(m, "disabled_reason", None):
            kept_modules.append(m)
            continue
        host = _service_key(m.url_main)
        here = list(by_host.get(host, ())) if host else []
        for site in profile_alias_sites(m, eligible_sites):
            if not any(site is existing for existing in here):
                here.append(site)
        if not here:
            kept_modules.append(m)
            continue
        if getattr(m, "source", None) == "user-scanner" and ctx is not None:
            options = ctx.options or {}
            if (options.get("extract") is False or options.get("impersonate") is False
                    or (ctx.http is not None and getattr(ctx.http, "impersonate_target", True) is None)):
                paired.append((here[0].id, m.id))
                continue
        selected = [s for s in here if same_selected_profile(m, s)]
        if selected:
            for s in selected:
                drop_sites.add(id(s))
                paired.append((m.id, s.id))
            kept_modules.append(m)
            continue
        # Newly reviewed creator/user routes are distinct from older numeric-ID,
        # channel or project routes on the same host. Keep both scopes explicit.
        if m.id in {'us-user-creator-indiegogo', 'us-user-creator-rumble', 'us-user-creator-kickstarter'}:
            kept_modules.append(m)
            continue
        if all(prefer_profile_module(m, s) or prefer_page_module(m, s, query) or same_selected_profile(m, s) for s in here):
            for s in here:
                drop_sites.add(id(s))
                paired.append((m.id, s.id))
            kept_modules.append(m)
            continue
        strong = [s for s in here if not getattr(s, "weak", False)]
        if strong:
            paired.append((strong[0].id, m.id))          # a rule with markers keeps the service
        else:
            for s in here:                                # only status-only guesses: the module's logic is better
                drop_sites.add(id(s))
                paired.append((m.id, s.id))
            kept_modules.append(m)
    return [s for s in sites if id(s) not in drop_sites], kept_modules, paired


def limit_plan(sites, modules, limit, catalogue, pairs=()):
    """Cap the reconciled plan with equal site/module shares where available.

    Rank within each share, not across competing pools. The best-ranked head
    gets the odd slot; once one pool runs out, the other fills remaining slots.
    Unknown ranks sort last within their pool. Replacement checks inherit their
    catalogue alternative's rank, including aliases whose hosts differ. Code
    modules are not guaranteed enrichment. Execution restrictions are unchanged.
    """
    from itertools import islice, zip_longest

    ranks, services = {}, {}
    for site in catalogue:
        if site.rank and site.rank > 0:
            ranks[("site", site.id)] = site.rank
            key = _site_service_key(site)
            if key:
                services[key] = min(services.get(key, float("inf")), site.rank)
    for module in modules:
        ranks[("module", module.id)] = services.get(_service_key(module.url_main), float("inf"))
    for kept, alternative in pairs:
        key = ("module", kept)
        if key in ranks:
            ranks[key] = min(ranks[key], ranks.get(("site", alternative), float("inf")))
    candidates = [("site", s) for s in sites] + [("module", m) for m in modules]
    candidates.sort(key=lambda item: (ranks.get((item[0], item[1].id), float("inf")),
                                      -len(getattr(item[1], "sources", ())), item[1].id, item[0]))
    by_kind = {kind: [item for item in candidates if item[0] == kind] for kind in ("site", "module")}
    first = candidates[0][0] if candidates else "site"
    second = "module" if first == "site" else "site"
    balanced = (item for pair in zip_longest(by_kind[first], by_kind[second])
                for item in pair if item is not None)
    chosen = list(islice(balanced, min(limit, len(candidates))))
    return ([item for kind, item in chosen if kind == "site"],
            [item for kind, item in chosen if kind == "module"])


def kind_for(query_type: QueryType) -> str:
    return {QueryType.USERNAME: "username", QueryType.EMAIL: "email", QueryType.PHONE: "phone"}.get(query_type, "username")


__all__ = ["Context", "Module", "load_family", "all_modules", "dedupe_modules", "reconcile_plan", "kind_for", "Status"]
