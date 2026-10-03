"""Presence-check plugin contract + auto-discovery registry.

Add a site by dropping one file in this package that subclasses `PresenceCheck`
and is decorated with `@register_presence`. The engine discovers and runs every
registered check concurrently.

Consensus: vendored from numint (src/numint/presence/base.py, commit 9186c35,
2026-07-18).  The two absolute ``numint.presence`` imports inside
``discover_presence`` were rewritten to ``consensus_osint.vendor.numint.presence``;
nothing else was changed.
"""

from __future__ import annotations

import abc
import importlib
import pkgutil
import time

import httpx

from ..core.models import PresenceResult

_REGISTRY: list[type[PresenceCheck]] = []

#: Rotating desktop Chrome UAs (mirrors ignorant's localuseragent list).
CHROME_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
]


def register_presence(cls: type[PresenceCheck]) -> type[PresenceCheck]:
    """Class decorator that adds a presence check to the registry."""
    if cls not in _REGISTRY:
        _REGISTRY.append(cls)
    return cls


def discover_presence() -> list[type[PresenceCheck]]:
    """Import every module in this package so `@register_presence` runs."""
    import consensus_osint.vendor.numint.presence as pkg

    for mod in pkgutil.iter_modules(pkg.__path__):
        # `base` is the contract; `_`-prefixed modules are templates/disabled.
        if mod.name == "base" or mod.name.startswith("_"):
            continue
        importlib.import_module(f"consensus_osint.vendor.numint.presence.{mod.name}")
    return list(_REGISTRY)


class PresenceCheck(abc.ABC):
    """Abstract base for one site's account-presence check."""

    #: Stable, human-readable site name (shown as the row label).
    site: str = "base"
    #: Which flow the signal comes from - audit trail, shown to the user.
    method: str = "lookup"  # lookup | reset | signup
    #: True only for checks whose endpoint never notifies the target.
    #: Bundled checks MUST be non-notifying.
    non_notifying: bool = True

    @abc.abstractmethod
    async def _check(
        self, number, client: httpx.AsyncClient
    ) -> PresenceResult:
        """Perform the probe. Implemented per site. May raise freely."""

    async def check(self, number, client: httpx.AsyncClient) -> PresenceResult:
        """Wrap `_check` with timing and uniform error isolation.

        One misbehaving site never crashes the scan; it becomes an `error`
        row instead.
        """
        start = time.monotonic()
        try:
            result = await self._check(number, client)
        except httpx.HTTPError as exc:
            result = PresenceResult(
                site=self.site,
                registered="error",
                method=self.method,
                error=f"HTTP error: {exc.__class__.__name__}",
            )
        except Exception as exc:  # noqa: BLE001 - isolate every failure
            result = PresenceResult(
                site=self.site,
                registered="error",
                method=self.method,
                error=f"{exc.__class__.__name__}: {exc}",
            )
        result.elapsed_ms = int((time.monotonic() - start) * 1000)
        return result
