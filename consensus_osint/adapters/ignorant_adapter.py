"""Adapter exposing the vendored ignorant phone-number modules as Consensus :class:`Module` objects.

ignorant (https://github.com/megadose/ignorant, GPL-3.0, vendored under
:mod:`consensus_osint.vendor.ignorant`) is holehe's sibling for phone numbers: one file
per site under ``modules/<category>/<site>.py`` defining
``async def <site>(phone, country_code, client, out)``, where ``phone`` is the
national number (digits only) and ``country_code`` the calling code (digits only,
no ``+``), both as strings - exactly what its CLI receives from ``ignorant 33 644637111``.

Consensus carries phone numbers as E.164 strings (``"+33644637111"``); :func:`split_e164`
converts them with the ``phonenumbers`` library.  Module discovery and result mapping
are shared with :mod:`consensus_osint.adapters.holehe_adapter`.
"""
from __future__ import annotations

import logging
from collections.abc import Callable

import phonenumbers

from ..core.models import Finding
from ..core.modules import Context, Module
from ..vendor.ignorant import modules as _ignorant_modules
from .holehe_adapter import SiteFunction, iter_site_functions, result_to_finding

log = logging.getLogger("consensus.adapters.ignorant")

SOURCE = "ignorant"
KIND = "phone"
ID_PREFIX = "ignorant-"

#: dotted module name -> error text for vendored modules that could not be loaded
#: during the last :func:`load_modules` call.
IMPORT_FAILURES: dict[str, str] = {}


def split_e164(query: str) -> tuple:
    """Split a phone string into the ``(country_code, national_number)`` digit strings ignorant expects.

    ``"+14155552671"`` -> ``("1", "4155552671")``.  A missing leading ``+`` is tolerated
    (the digits are then read as an international number).  The national part is
    ``phonenumbers.national_significant_number`` so a significant leading zero
    (Italy, Ivory Coast ...) survives.  Raises ``phonenumbers.NumberParseException``
    for input that is not a phone number.
    """
    q = query.strip()
    try:
        number = phonenumbers.parse(q, None)
    except phonenumbers.NumberParseException:
        if q.startswith("+") or not q:
            raise
        number = phonenumbers.parse("+" + q, None)
    return str(number.country_code), phonenumbers.national_significant_number(number)


def _make_check(sf: SiteFunction, module_id: str, loud: bool) -> Callable:
    async def check(query: str, ctx: Context) -> Finding:
        try:
            from ..core.phone import parse_number as describe_number

            info = describe_number(query)
            if not info.get("valid"):
                raise ValueError(info.get("error") or "invalid number")
            if not info.get("online_allowed"):
                return Finding.skipped(query, KIND, sf.name, module_id,
                                       "phone checks require a valid number with an explicit country code",
                                       source=SOURCE, category=sf.category, url=sf.url_main)
            country_code, national = split_e164(info["e164"])
        except Exception as exc:  # noqa: BLE001 - NumberParseException or anything odd
            return Finding.error_result(query, KIND, sf.name, module_id, f"invalid phone number: {exc}",
                                        source=SOURCE, category=sf.category, url=sf.url_main,
                                        method=sf.method, loud=loud)
        out: list = []
        try:
            await sf.func(national, country_code, ctx.client, out)
        except Exception as exc:  # noqa: BLE001 - third-party module code
            return Finding.error_result(query, KIND, sf.name, module_id, f"{type(exc).__name__}: {exc}",
                                        source=SOURCE, category=sf.category, url=sf.url_main,
                                        method=sf.method, loud=loud)
        return result_to_finding(out, query=query, kind=KIND, source=SOURCE, site_id=module_id,
                                 name=sf.name, category=sf.category, url_main=sf.url_main,
                                 method=sf.method, loud=loud)

    check.__name__ = check.__qualname__ = f"ignorant_{sf.site}"
    return check


def load_modules() -> list:
    """Return one :class:`Module` per vendored ignorant site, sorted by id (never raises)."""
    IMPORT_FAILURES.clear()
    modules: dict[str, Module] = {}
    for sf in iter_site_functions(_ignorant_modules, IMPORT_FAILURES):
        module_id = ID_PREFIX + sf.site
        if module_id in modules:
            IMPORT_FAILURES[f"{_ignorant_modules.__name__}.{sf.category}.{sf.site}"] = f"duplicate module id {module_id}"
            continue
        loud = sf.method == "password recovery"
        modules[module_id] = Module(
            id=module_id,
            name=sf.name,
            kind=KIND,
            check=_make_check(sf, module_id, loud),
            category=sf.category,
            source=SOURCE,
            url_main=sf.url_main,
            loud=loud,
            method=sf.method,
        )
    log.debug("ignorant adapter: %d modules loaded, %d import failures", len(modules), len(IMPORT_FAILURES))
    return [modules[k] for k in sorted(modules)]


__all__ = ["load_modules", "split_e164", "IMPORT_FAILURES", "SOURCE", "KIND"]
