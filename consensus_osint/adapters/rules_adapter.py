"""Adapter exposing the data rules (``consensus_osint/data/rules.json``) as :class:`Module`s.

Unlike the other adapters in this package, which wrap *vendored code*, this one is
fed by data maintained by Consensus: every rule becomes one :class:`Module` of its
``kind`` whose ``check`` runs :func:`consensus_osint.core.rules.check_rule` against
the scan's shared ``httpx`` client (``ctx.client``).

A rule that names a ``replaces`` module supersedes that code module: the code
adapters ask :func:`replaced_ids` and skip it, so one service is asked once.
``url_main`` is the rule's page URL, which is what the (kind, host) de-duplication
and ``--site`` matching key on.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from ..core.models import Finding
from ..core.modules import Context, Module
from ..core.rules import ID_PREFIX, KINDS, SOURCE, check_rule, load_rules
from ..core.rules import replaced_ids as _replaced_ids

log = logging.getLogger("consensus.adapters.rules")

METHOD = "data rule"


def replaced_ids() -> set:
    """Ids of code modules superseded by a rule (never raises)."""
    try:
        return _replaced_ids()
    except Exception:  # noqa: BLE001
        log.debug("could not read the replaced-module list", exc_info=True)
        return set()


def _make_check(entry: dict) -> Callable[[str, Context], Awaitable[Finding]]:
    async def check(query: str, ctx: Context) -> Finding:
        # a rule that needs browser TLS impersonation goes through Consensus's Http wrapper
        http = getattr(ctx, "http", None) if entry.get("impersonate") else None
        return await check_rule(entry, query, http or ctx.client,
                                extract=ctx.options.get("extract", True), allow_loud=ctx.allow_loud)

    check.__name__ = check.__qualname__ = "check_" + str(entry.get("id", "")).replace("-", "_")
    return check


def load_modules() -> list[Module]:
    """Return one :class:`Module` per rule (never raises)."""
    modules: list[Module] = []
    seen: set[str] = set()
    for entry in load_rules():
        eid = str(entry.get("id") or "").strip()
        kind = entry.get("kind") or "email"
        if not eid or kind not in KINDS:
            continue
        module_id = ID_PREFIX + eid
        if module_id in seen:
            log.debug("duplicate rule id %s skipped", module_id)
            continue
        seen.add(module_id)
        tags = [t for t in (entry.get("source"),) if t]
        if entry.get("replaces"):
            tags.append("translated")
        modules.append(Module(
            id=module_id,
            name=entry.get("name") or eid,
            kind=kind,
            check=_make_check(entry),
            category=entry.get("category", "misc"),
            source=SOURCE,
            url_main=entry.get("url") or entry.get("check_url"),
            loud=bool(entry.get("loud")),
            nsfw=bool(entry.get("nsfw")),
            tags=tags,
            method=METHOD,
            replaces=entry.get("replaces"),
        ))
    log.debug("rules adapter: %d modules loaded", len(modules))
    return modules


__all__ = ["load_modules", "replaced_ids", "SOURCE", "METHOD"]
