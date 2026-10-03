"""Shared namespace for the vendored holehe site modules.

Upstream holehe (https://github.com/megadose/holehe, GPL-3.0) keeps its library
helpers and its command line front-end together in ``holehe/core.py``.  Every
site module starts with ``from holehe.core import *`` and relies on the names
that star-import drags in: ``random``, ``string``, ``re``, ``json``,
``hashlib``, ``datetime``, ``BeautifulSoup``, ``httpx`` and ``ua``.

This vendored copy keeps exactly those names plus the small library helpers
(``import_submodules``, ``get_functions``, ``is_email``, ``launch_module``).
The CLI (argument parsing, coloured printing, CSV export), the self-update
routine and the tqdm/trio progress instrument were dropped; Consensus drives the
modules through :mod:`consensus_osint.adapters.holehe_adapter` instead.
"""
from bs4 import BeautifulSoup
import httpx

import importlib
import inspect
import ast
import textwrap
import pkgutil
import hashlib
import re
import string
import random
import json
from datetime import datetime

from consensus_osint.vendor.holehe.localuseragent import ua
from consensus_osint.core.provider_contracts import has_service_error

try:  # only holehe's own trio based runner needs trio; the site modules do not
    import trio
except ImportError:  # pragma: no cover
    trio = None


DEBUG        = False
EMAIL_FORMAT = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

__version__ = "1.61"


def append_http_error(response, out, name, domain, method, accepted=(200,)):
    """Keep unavailable endpoints separate from account evidence.

    A caller must explicitly allow any non-200 code used by its provider contract.
    Return True when the response was recorded and parsing must stop.
    """
    challenge = response.headers.get("cf-mitigated", "").lower() == "challenge"
    if response.status_code in accepted and not challenge:
        return False
    out.append({"name": name, "domain": domain, "method": method,
                "frequent_rate_limit": False, "exists": None, "unknown": True,
                "rateLimit": response.status_code == 429,
                "blocked": challenge or response.status_code in (401, 403, 406, 407, 418, 451),
                "http_status": response.status_code,
                "reason": "Provider challenge; account status is unknown." if challenge else f"Lookup request returned HTTP {response.status_code}"})
    return True


def lookup_result(name, domain, method):
    return dict(name=name, domain=domain, method=method, frequent_rate_limit=False,
                rateLimit=False, exists=None, unknown=True,
                reason="Unrecognised lookup response; account status is unknown.")


def apply_mailbox_outcome(result, outcome, *, http_status=None):
    """Preserve the legacy fields while reporting typed mailbox-parser outcomes."""
    from consensus_osint.core.models import Status

    status, extra, reason = outcome
    result.update(exists=(status is Status.FOUND) if status.is_definitive else None,
                  unknown=not status.is_definitive, rateLimit=status is Status.RATE_LIMITED,
                  blocked=status is Status.BLOCKED, error=status is Status.ERROR, reason=reason)
    if http_status is not None:
        result["http_status"] = http_status
    extra = dict(extra)
    result["emailrecovery"] = extra.pop("recovery_email", None)
    result["phoneNumber"] = extra.pop("phone_hint", None)
    result["others"] = extra or None


def append_crm_outcome(response, out, name, domain, method, email):
    """Adapt the shared CRM contract to the retained Holehe result shape."""
    from consensus_osint.core.crm_contracts import crm_outcome
    from consensus_osint.core.models import Status

    status, reason = crm_outcome(name, response, email)
    result = lookup_result(name, domain, method)
    result.update(exists=(status is Status.FOUND) if status.is_definitive else None,
                  unknown=not status.is_definitive, rateLimit=status is Status.RATE_LIMITED,
                  blocked=status is Status.BLOCKED, http_status=response.status_code, reason=reason)
    out.append(result)


def read_lookup_response(response, result, *, html=False):
    """Guard status/challenges before consuming provider evidence or tokens."""
    result["http_status"] = response.status_code
    failures = []
    if append_http_error(response, failures, result["name"], result["domain"], result["method"]):
        result.update(failures[-1], frequent_rate_limit=result.get("frequent_rate_limit", False))
        return None
    if html:
        page = BeautifulSoup(response.text, "html.parser")
        if (page.select_one('#captchacharacters, input[name="cvf_captcha_input"], input[name="guess"]')
                or "robot check" in page.get_text(" ", strip=True).lower()):
            result.update(blocked=True, reason="Provider CAPTCHA; account status is unknown.")
            return None
        return page
    try:
        data = response.json()
    except ValueError:
        result["reason"] = "Malformed JSON; account status is unknown."
        return None
    if not isinstance(data, dict) or has_service_error(data):
        result["reason"] = "Unexpected or failed provider response; account status is unknown."
        return None
    return data


def append_jobs_learning_outcome(response, out, name, domain, method, query):
    from consensus_osint.core.jobs_learning_contracts import outcome
    from consensus_osint.core.models import Status

    status, extra, reason = outcome(name, response, query)
    result = lookup_result(name, domain, method)
    result.update(exists=(status is Status.FOUND) if status.is_definitive else None,
                  unknown=not status.is_definitive, rateLimit=status is Status.RATE_LIMITED,
                  blocked=status is Status.BLOCKED, http_status=response.status_code, reason=reason)
    if extra:
        result['others'] = extra
    out.append(result)


def _mybb_token(page):
    """Read one inline declaration, skipping comments and quoted examples.

    This is a bounded lexer for the retained declaration, not a JS evaluator.
    Other script types and unloaded external scripts are not prerequisites.
    """
    quoted = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    template = chr(96) + r"(?:\\.|[^" + chr(96) + r"\\])*" + chr(96)
    pattern = (r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted + "|" + template
               + r"|\bvar\s+my_post_key\s*=\s*(?P<quote>['\"])(?P<token>[0-9a-fA-F]{32})(?P=quote)\s*;")
    tokens = []
    for script in page.find_all("script"):
        kind = script.get("type", "").strip().lower()
        if script.has_attr("src") or kind not in ("", "module", "text/javascript", "application/javascript",
                                                  "text/ecmascript", "application/ecmascript"):
            continue
        tokens.extend(match["token"] for match in re.finditer(pattern, script.get_text()) if match["token"])
    return tokens[0] if len(tokens) == 1 else None


async def check_mybb(email, client, out, *, name, domain, method, frequent_rate_limit, base_url, headers):
    """Shared retained MyBB contract; each caller owns its exact forum scope.

    MyBB 1.8.38's email_availability handler returns an exact JSON error string
    or the JSON string 'true'. The latter does not prove absence: verify_email
    skips duplicate checks when allowmultipleemails is enabled. Deployed forum
    versions, plugin hooks and reliability require separate evidence.
    """
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    response = await client.get(base_url + "member.php", headers=headers)
    page = read_lookup_response(response, result, html=True)
    if page is None:
        out.append(result)
        return
    if "Your request was blocked" in response.text:
        result.update(blocked=True, reason="The forum blocked the request; account status is unknown.")
        out.append(result)
        return
    token = _mybb_token(page)
    if token is None:
        result["reason"] = "The forum lookup token was missing or ambiguous; no lookup was submitted."
        out.append(result)
        return
    headers = dict(headers, **{"X-Requested-With": "XMLHttpRequest"})
    response = await client.post(base_url + "xmlhttp.php", headers=headers,
        params={"action": "email_availability"}, data={"email": email, "my_post_key": token})
    page = read_lookup_response(response, result, html=True)
    if page is not None:
        if "Your request was blocked" in response.text:
            result.update(blocked=True, reason="The forum blocked the request; account status is unknown.")
        else:
            try:
                payload = response.json()
            except ValueError:
                payload = None
                result["reason"] = "Malformed forum JSON; account status is unknown."
            duplicate = ("You have entered an email address that is already in use by another member. "
                         "Please enter a different email address.")
            if payload == duplicate:
                result.update(exists=True, unknown=False, reason=None)
            elif payload == "true":
                result.update(others={"available": True}, reason=(
                    "The forum allowed this email for registration; this does not prove account absence "
                    "because the forum may allow several accounts per email."))
    out.append(result)


def import_submodules(package, recursive=True):
    """Get all the holehe submodules"""
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.iter_modules(package.__path__):
        full_name = package.__name__ + '.' + name
        results[full_name] = importlib.import_module(full_name)
        if recursive and is_pkg:
            results.update(import_submodules(full_name))
    return results


def get_functions(modules,args=None):
    """Transform the modules objects to functions"""
    websites = []

    for name, module in modules.items():
        site = name.rsplit(".", 1)[-1]
        candidate = getattr(module, site, None)
        if not inspect.iscoroutinefunction(candidate):
            continue
        if getattr(args, "nopasswordrecovery", False):
            # Read static method metadata, matching the adapter's convention.
            # Unknown/dynamic methods cannot promise to avoid recovery flows.
            try:
                tree = ast.parse(textwrap.dedent(inspect.getsource(candidate)))
            except (OSError, TypeError, SyntaxError):
                continue
            assignments = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == "method" for target in node.targets)]
            if (not assignments or any(not isinstance(value, ast.Constant) or not isinstance(value.value, str)
                                       or value.value == "password recovery" for value in assignments)):
                continue
        websites.append(candidate)
    return websites


def is_email(email: str) -> bool:
    """Check if the input is a valid email address

    Keyword Arguments:
    email       -- String to be tested

    Return Value:
    Boolean     -- True if string is an email, False otherwise
    """

    from consensus_osint.core.emailinfo import valid_syntax

    return valid_syntax(email)


async def launch_module(module,email, client, out):
    data={'aboutme': 'about.me', 'adobe': 'adobe.com', 'amazon': 'amazon.com', 'anydo': 'any.do', 'archive': 'archive.org', 'armurerieauxerre': 'armurerie-auxerre.com', 'atlassian': 'atlassian.com', 'babeshows': 'babeshows.co.uk', 'badeggsonline': 'badeggsonline.com', 'biosmods': 'bios-mods.com', 'biotechnologyforums': 'biotechnologyforums.com', 'bitmoji': 'bitmoji.com', 'blablacar': 'blablacar.com', 'blackworldforum': 'blackworldforum.com', 'blip': 'blip.fm', 'blitzortung': 'forum.blitzortung.org', 'bluegrassrivals': 'bluegrassrivals.com', 'bodybuilding': 'bodybuilding.com', 'buymeacoffee': 'buymeacoffee.com', 'cambridgemt': 'discussion.cambridge-mt.com', 'caringbridge': 'caringbridge.org', 'chinaphonearena': 'chinaphonearena.com', 'clashfarmer': 'clashfarmer.com', 'codecademy': 'codecademy.com', 'codeigniter': 'forum.codeigniter.com', 'codepen': 'codepen.io', 'coroflot': 'coroflot.com', 'cpaelites': 'cpaelites.com', 'cpahero': 'cpahero.com', 'cracked_to': 'cracked.to', 'crevado': 'crevado.com', 'deliveroo': 'deliveroo.com', 'demonforums': 'demonforums.net', 'devrant': 'devrant.com', 'diigo': 'diigo.com', 'discord': 'discord.com', 'docker': 'docker.com', 'dominosfr': 'dominos.fr', 'ebay': 'ebay.com', 'ello': 'ello.co', 'envato': 'envato.com', 'eventbrite': 'eventbrite.com', 'evernote': 'evernote.com', 'fanpop': 'fanpop.com', 'firefox': 'firefox.com', 'flickr': 'flickr.com', 'freelancer': 'freelancer.com', 'freiberg': 'drachenhort.user.stunet.tu-freiberg.de', 'garmin': 'garmin.com', 'github': 'github.com', 'google': 'google.com', 'gravatar': 'gravatar.com', 'imgur': 'imgur.com', 'instagram': 'instagram.com', 'issuu': 'issuu.com', 'koditv': 'forum.kodi.tv', 'komoot': 'komoot.com', 'laposte': 'laposte.fr', 'lastfm': 'last.fm', 'lastpass': 'lastpass.com', 'mail_ru': 'mail.ru', 'mybb': 'community.mybb.com', 'myspace': 'myspace.com', 'nattyornot': 'nattyornotforum.nattyornot.com', 'naturabuy': 'naturabuy.fr', 'ndemiccreations': 'forum.ndemiccreations.com', 'nextpvr': 'forums.nextpvr.com', 'nike': 'nike.com', 'odnoklassniki': 'ok.ru', 'office365': 'office365.com', 'onlinesequencer': 'onlinesequencer.net', 'parler': 'parler.com', 'patreon': 'patreon.com', 'pinterest': 'pinterest.com', 'plurk': 'plurk.com', 'pornhub': 'pornhub.com', 'protonmail': 'protonmail.ch', 'quora': 'quora.com', 'rambler': 'rambler.ru', 'redtube': 'redtube.com', 'replit': 'replit.com', 'rocketreach': 'rocketreach.co', 'samsung': 'samsung.com', 'seoclerks': 'seoclerks.com', 'sevencups': '7cups.com', 'smule': 'smule.com', 'snapchat': 'snapchat.com', 'soundcloud': 'soundcloud.com', 'sporcle': 'sporcle.com', 'spotify': 'spotify.com', 'strava': 'strava.com', 'taringa': 'taringa.net', 'teamtreehouse': 'teamtreehouse.com', 'tellonym': 'tellonym.me', 'thecardboard': 'thecardboard.org', 'therianguide': 'forums.therian-guide.com', 'thevapingforum': 'thevapingforum.com', 'tumblr': 'tumblr.com', 'tunefind': 'tunefind.com', 'twitter': 'twitter.com', 'venmo': 'venmo.com', 'vivino': 'vivino.com', 'voxmedia': 'voxmedia.com', 'vrbo': 'vrbo.com', 'vsco': 'vsco.co', 'wattpad': 'wattpad.com', 'wordpress': 'wordpress.com', 'xing': 'xing.com', 'xnxx': 'xnxx.com', 'xvideos': 'xvideos.com', 'yahoo': 'yahoo.com','hubspot': 'hubspot.com', 'pipedrive': 'pipedrive.com', 'insightly': 'insightly.com', 'nutshell': 'nutshell.com', 'zoho': 'zoho.com', 'axonaut': 'axonaut.com', 'amocrm': 'amocrm.com', 'nimble': 'nimble.com', 'nocrm': 'nocrm.io', 'teamleader': 'teamleader.eu'}
    pending = []
    try:
        await module(email, client, pending)
    except Exception as exc:
        name = getattr(module, "__name__", "unknown")
        out.append({"name": name, "domain": data.get(name), "rateLimit": False,
                    "error": True, "exists": None, "reason": "Email lookup failed: " + type(exc).__name__})
    else:
        out.extend(pending)
