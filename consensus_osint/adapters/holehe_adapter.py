"""Adapter exposing the vendored holehe e-mail modules as Consensus :class:`Module` objects.

holehe (https://github.com/megadose/holehe, GPL-3.0, vendored under
:mod:`consensus_osint.vendor.holehe`) ships one file per site under
``modules/<category>/<site>.py``.  Each file defines
``async def <site>(email, client, out)`` which appends a result dict to ``out``::

    {"name": "...", "domain": "...", "method": "register" | "login" | "password recovery" | "other",
     "frequent_rate_limit": bool, "rateLimit": bool, "exists": bool | None,
     "emailrecovery": str | None, "phoneNumber": str | None, "others": dict | None}

:func:`load_modules` walks that package with ``pkgutil.walk_packages`` (the same
way holehe's own ``import_submodules`` does) and wraps every site coroutine.  The
generic pieces - :func:`iter_site_functions` and :func:`result_to_finding` - are
shared with :mod:`consensus_osint.adapters.ignorant_adapter`, because ignorant is
holehe's twin for phone numbers and uses the identical module layout.
"""
from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from ..core.models import Finding, Status
from ..core.modules import Context, Module
from ..vendor.holehe import modules as _holehe_modules

log = logging.getLogger("consensus.adapters.holehe")

SOURCE = "holehe"
KIND = "email"
ID_PREFIX = "holehe-"

#: The modules holehe's ``--no-password-recovery`` flag excludes.  They drive the
#: site's password-reset flow, which may send a reset e-mail to the target, so they
#: are always marked ``loud`` (on top of any module whose ``method`` says so).
PASSWORD_RECOVERY_MODULES = frozenset({"adobe", "mail_ru", "odnoklassniki", "samsung"})

#: dotted module name -> error text for vendored modules that could not be loaded
#: during the last :func:`load_modules` call.  A broken module never breaks the
#: family; it is skipped and recorded here.
IMPORT_FAILURES: dict[str, str] = {}

_NAME_RE = re.compile(r'^\s*name\s*=\s*["\']([^"\']+)["\']', re.M)
_DOMAIN_RE = re.compile(r'^\s*domain\s*=\s*["\']([^"\']+)["\']', re.M)
_METHOD_RE = re.compile(r'^\s*method\s*=\s*["\']([^"\']+)["\']', re.M)


# ---------------------------------------------------------------------------
# generic helpers (also used by the ignorant adapter)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SiteFunction:
    """One vendored site coroutine plus the metadata scraped from its source text."""

    category: str                 # directory name: forum, social_media, shopping ...
    site: str                     # file / function name, e.g. "gravatar"
    func: Callable
    name: str                     # the module's ``name = "..."`` value (falls back to ``site``)
    domain: str | None         # the module's ``domain = "..."`` value
    method: str | None         # "register" | "login" | "password recovery" | "other"

    @property
    def url_main(self) -> str | None:
        return f"https://{self.domain}" if self.domain else None


def _first(pattern: re.Pattern, text: str) -> str | None:
    m = pattern.search(text)
    return m.group(1).strip() if m else None


def _source_text(pymod: ModuleType) -> str:
    path = getattr(pymod, "__file__", None)
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def iter_site_functions(package: ModuleType, failures: dict) -> Iterator[SiteFunction]:
    """Yield a :class:`SiteFunction` for every ``<category>/<site>.py`` below *package*.

    Modules that fail to import, or that do not define a coroutine named after their
    file, are recorded in *failures* (dotted name -> reason) and skipped.
    """
    prefix = package.__name__ + "."

    def _onerror(name: str) -> None:
        failures[name] = "package could not be imported"

    for info in pkgutil.walk_packages(package.__path__, prefix, onerror=_onerror):
        if info.ispkg:
            continue
        parts = info.name[len(prefix):].split(".")
        if len(parts) != 2:            # only <category>.<site> leaves are site modules
            continue
        category, site = parts
        try:
            pymod = importlib.import_module(info.name)
        except Exception as exc:  # noqa: BLE001 - third-party code; keep loading the rest
            failures[info.name] = f"{type(exc).__name__}: {exc}"
            log.warning("vendored module %s failed to import: %s", info.name, exc)
            continue
        func = getattr(pymod, site, None)
        if not inspect.iscoroutinefunction(func):
            failures[info.name] = f"no coroutine function named {site!r}"
            log.warning("vendored module %s defines no coroutine %r", info.name, site)
            continue
        src = _source_text(pymod)
        yield SiteFunction(
            category=category,
            site=site,
            func=func,
            name=_first(_NAME_RE, src) or site,
            domain=_first(_DOMAIN_RE, src),
            method=_first(_METHOD_RE, src),
        )


def result_to_finding(out: list, *, query: str, kind: str, source: str, site_id: str, name: str,
                      category: str, url_main: str | None, method: str | None,
                      loud: bool = False) -> Finding:
    """Map a holehe / ignorant result dict (the last one appended to *out*) onto a Finding.

    ``rateLimit`` True -> RATE_LIMITED; ``exists`` True -> FOUND; ``exists`` False ->
    NOT_FOUND. Reviewed parsers can explicitly report ``unknown`` or ``blocked``;
    missing verdicts without that explanation and ``"error": True`` become ERROR.
    ``emailrecovery`` / ``phoneNumber`` / ``others`` land in ``Finding.extra`` as
    ``recovery_email`` / ``phone_hint`` / ``others`` when they are not None.
    """
    base = dict(query=query, query_type=kind, site=name, site_id=site_id, url=url_main,
                category=category, source=source, method=method, loud=loud)
    if not out:
        return Finding(status=Status.ERROR, error="module produced no result", **base)
    res = out[-1]
    if not isinstance(res, dict):
        return Finding(status=Status.ERROR, error=f"unexpected module output: {type(res).__name__}", **base)

    extra: dict = {}
    for src_key, dst_key in (("emailrecovery", "recovery_email"),
                             ("phoneNumber", "phone_hint"),
                             ("others", "others")):
        value = res.get(src_key)
        if value is not None:
            extra[dst_key] = value

    error: str | None = None
    if res.get("rateLimit"):
        status = Status.RATE_LIMITED
    elif res.get("blocked") is True:
        status = Status.BLOCKED
    elif res.get("error"):
        status = Status.ERROR
        others = res.get("others")
        error = str(others.get("errorMessage")) if isinstance(others, dict) and others.get("errorMessage") else "module reported an error"
    elif res.get("unknown") is True:
        status = Status.UNKNOWN
    elif res.get("exists") is True:
        status = Status.FOUND
    elif res.get("exists") is False:
        status = Status.NOT_FOUND
    else:
        status = Status.ERROR
        error = "module returned no verdict"
    if not status.is_definitive and isinstance(res.get("reason"), str):
        error = res["reason"] or error
    http_status = res.get("http_status")
    if type(http_status) is not int or not 100 <= http_status <= 599:
        http_status = None
    return Finding(status=status, extra=extra, error=error, http_status=http_status, **base)


# ---------------------------------------------------------------------------
# holehe modules
# ---------------------------------------------------------------------------
def _make_check(sf: SiteFunction, module_id: str, loud: bool) -> Callable:
    async def check(query: str, ctx: Context) -> Finding:
        out: list = []
        try:
            await sf.func(query, ctx.client, out)
        except Exception as exc:  # noqa: BLE001 - third-party module code
            return Finding.error_result(query, KIND, sf.name, module_id, f"{type(exc).__name__}: {exc}",
                                        source=SOURCE, category=sf.category, url=sf.url_main,
                                        method=sf.method, loud=loud)
        return result_to_finding(out, query=query, kind=KIND, source=SOURCE, site_id=module_id,
                                 name=sf.name, category=sf.category, url_main=sf.url_main,
                                 method=sf.method, loud=loud)

    check.__name__ = check.__qualname__ = f"holehe_{sf.site}"
    return check


def load_modules() -> list:
    """Return one :class:`Module` per vendored holehe site, sorted by id (never raises)."""
    IMPORT_FAILURES.clear()
    modules: dict[str, Module] = {}
    for sf in iter_site_functions(_holehe_modules, IMPORT_FAILURES):
        module_id = ID_PREFIX + sf.site
        if module_id in modules:
            IMPORT_FAILURES[f"{_holehe_modules.__name__}.{sf.category}.{sf.site}"] = f"duplicate module id {module_id}"
            continue
        loud = sf.site in PASSWORD_RECOVERY_MODULES or sf.method == "password recovery"
        modules[module_id] = Module(
            id=module_id,
            name=sf.name,
            kind=KIND,
            check=_make_check(sf, module_id, loud),
            category=sf.category,
            source=SOURCE,
            url_main=sf.url_main,
            loud=loud,
            nsfw=sf.category == "porn",
            method=sf.method,
        )
    log.debug("holehe adapter: %d modules loaded, %d import failures", len(modules), len(IMPORT_FAILURES))
    return [modules[k] for k in sorted(modules)]


__all__ = ["load_modules", "result_to_finding", "iter_site_functions", "SiteFunction",
           "PASSWORD_RECOVERY_MODULES", "IMPORT_FAILURES", "SOURCE", "KIND"]
