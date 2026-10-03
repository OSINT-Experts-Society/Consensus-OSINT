"""Shared namespace for the vendored ignorant phone-number modules.

Upstream ignorant (https://github.com/megadose/ignorant, GPL-3.0) is holehe's
sibling for phone numbers. Upstream site modules start with
``from ignorant.core import *`` and relies on the names that star-import drags
in: ``random``, ``json``, ``hashlib``, ``hmac``, ``urllib.parse``,
``BeautifulSoup``, ``httpx`` and ``ua``.

This vendored copy keeps those compatibility names plus the library helpers
(``import_submodules``, ``get_functions``, ``launch_module``).  The CLI, the
self-update routine and the tqdm/trio progress instrument were dropped; Consensus
drives the modules through :mod:`consensus_osint.adapters.ignorant_adapter`.
Maintained site modules use explicit imports; Numint can discover its registry
without importing this optional compatibility namespace.
"""
from bs4 import BeautifulSoup
import hashlib
import hmac
import httpx
import importlib
import inspect
import json
import pkgutil
import random
import re
import string
import urllib.parse

from consensus_osint.vendor.ignorant.localuseragent import ua

try:  # only ignorant's own trio based runner needs trio; the site modules do not
    import trio
except ImportError:  # pragma: no cover
    trio = None

DEBUG = False

__version__ = "1.2"


def import_submodules(package, recursive=True):
    """Get all the ignorant submodules"""
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.iter_modules(package.__path__):
        full_name = package.__name__ + '.' + name
        results[full_name] = importlib.import_module(full_name)
        if recursive and is_pkg:
            results.update(import_submodules(full_name))
    return results

def get_functions(modules, args=None):
    """Transform the modules objects to functions"""
    websites = []

    for name, module in modules.items():
        candidate = getattr(module, name.rsplit(".", 1)[-1], None)
        if inspect.iscoroutinefunction(candidate):
            websites.append(candidate)
    return websites


async def launch_module(module, phone, country_code, client, out):
    data={'amazon':'amazon.com','instagram':'instagram.com','snapchat': 'snapchat.com'}
    pending = []
    try:
        # Providers assemble results before awaiting requests. Keep those
        # provisional rows private until the module finishes successfully.
        await module(phone, country_code, client, pending)
    except Exception as exc:
        # Cancellation belongs to the caller; failures are not account absence
        # or rate limiting. Do not expose response bodies from exception text.
        name = getattr(module, "__name__", "unknown")
        out.append({"name": name, "domain": data.get(name),
                    "rateLimit": False, "exists": None, "error": True,
                    "reason": "Phone lookup failed: " + type(exc).__name__})
    else:
        out.extend(pending)
