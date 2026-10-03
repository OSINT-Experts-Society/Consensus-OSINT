"""Phone-number analysis.

* **Offline analysis** with python-phonenumbers (bundles libphonenumber's
  carrier, geocoder and timezone tables): validity, formats, country, region,
  carrier, timezones, line type — the equivalent of phoneinfoga's ``local``
  scanner and the Phunter / PhoneNumber-OSINT lookups.
* **Search dorks**: phoneinfoga's categorised Google dorks (GPL-3.0, social /
  disposable / reputation / individuals / general) built as real search URLs
  for Google, Bing, DuckDuckGo and Yandex, plus the direct people-search URLs
  used by Telespotter (MIT) for North-American numbers.  Site lists live in
  ``data/phone_dorks.yaml``.
* **Keyless reputation**: best-effort scraping of Tellows (country domains)
  and SpamCalls.net, an idea shared by Phunter, phoneintel and Moriarty.
* **Optional keyed providers**: numverify and AbstractAPI (only when a key is
  configured), OVH Telecom's public number-zone list (phoneinfoga's ``ovh``
  scanner, FR/BE/GB/ES/CH) and Google Custom Search.

Nothing here raises for bad input: every public function returns data or
:class:`Finding` objects with an ERROR / BLOCKED status instead.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Awaitable, Callable
from functools import lru_cache
from html import unescape
from pathlib import Path
from urllib.parse import quote_plus, urlencode, urlsplit

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

from .config import get_key
from .errors import detect_error_page
from .http import Http, Response
from .models import Finding, Status
from .phone_reputation import evidence_page

log = logging.getLogger("consensus.phone")

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "phone_dorks.yaml"
SOURCE = "phone"
QUERY_TYPE = "phone"

#: Regions tried, in order, for numbers given without a leading "+" or a default region.
COMMON_REGIONS = [
    "US", "GB", "CA", "AU", "IN", "DE", "FR", "ES", "IT", "NL", "BR", "MX", "RU", "ZA", "NG", "PK", "ID",
    "PH", "TR", "PL", "UA", "AR", "CO", "EG", "SA", "AE", "JP", "KR", "CN", "IE", "SE", "NO", "DK", "FI",
    "PT", "BE", "CH", "AT", "NZ",
]

DORK_CATEGORIES = ("social", "disposable", "reputation", "individuals", "general", "people-search")

#: Document extensions searched by phoneinfoga's "general" dork.
DOC_EXTS = ["doc", "docx", "odt", "pdf", "rtf", "sxw", "psw", "ppt", "pptx", "pps", "csv", "txt", "xls"]

#: Tellows country sites (from the site's own footer).  Country domains take the
#: *national* digits in the path; the international tellows.com takes E.164 digits.
TELLOWS_DOMAINS = {
    "AT": "tellows.at", "BE": "tellows.be", "CH": "tellows.ch", "CO": "tellows.co", "NZ": "tellows.co.nz",
    "GB": "tellows.co.uk", "ZA": "tellows.co.za", "US": "tellows.com", "BR": "tellows.com.br", "CZ": "tellows.cz",
    "DE": "tellows.de", "ES": "tellows.es", "FR": "tellows.fr", "GR": "tellows.gr", "HU": "tellows.hu",
    "IN": "tellows.in", "IT": "tellows.it", "JP": "tellows.jp", "MX": "tellows.mx", "NL": "tellows.nl",
    "PL": "tellows.pl", "PT": "tellows.pt", "RU": "tellows.ru", "SE": "tellows.se", "TW": "tellows.tw",
}

#: Countries covered by OVH Telecom's detailedZones endpoint (phoneinfoga ovh scanner).
OVH_REGIONS = {"FR", "BE", "GB", "ES", "CH"}

# Built-in online stages obey the same user scope as code-module lookups.
SERVICES = {
    "phone-tellows": ("Tellows", "reputation", tuple(TELLOWS_DOMAINS.values())),
    "phone-spamcalls": ("SpamCalls", "reputation", ("spamcalls.net",)),
    "phone-shouldianswer": ("ShouldIAnswer", "reputation", ("shouldianswer.com",)),
    "phone-cleverdialer": ("CleverDialer", "reputation", ("cleverdialer.com", "cleverdialer.de")),
    "phone-numverify": ("Numverify", "validation", ("numverify.com", "apilayer.net")),
    "phone-abstractapi": ("AbstractAPI", "validation", ("abstractapi.com", "phonevalidation.abstractapi.com")),
    "phone-ovh": ("OVH Telecom", "carrier", ("ovh.com", "api.ovh.com")),
    "phone-googlecse": ("Google CSE", "search", ("google.com", "www.googleapis.com")),
}


def service_keys(service_id: str) -> set[str]:
    from .sitesdb import domain_words

    name, _, hosts = SERVICES[service_id]
    keys = {service_id, service_id.removeprefix("phone-"), name.lower(), *hosts}
    for host in hosts:
        keys.update(domain_words(host))
        keys.add(host.removeprefix("www."))
        if not host.startswith("www."):
            keys.add("www." + host)
    return keys


def select_services(*, ids=None, exclude=None, tags=None, exclude_tags=None) -> set[str]:
    only, skip, include_categories, skip_categories = (
        {str(value).lower() for value in values or []}
        for values in (ids, exclude, tags, exclude_tags)
    )
    return {ident for ident, (_, category, _) in SERVICES.items()
            if (not only or service_keys(ident) & only) and not service_keys(ident) & skip
            and (not include_categories or category in include_categories) and category not in skip_categories}

_HTML_ACCEPT = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
_JSON_ACCEPT = {"Accept": "application/json"}

_TYPE_NAMES = {v: k for k, v in vars(PhoneNumberType).items() if isinstance(v, int) and k.isupper()}
_VALIDATION_NAMES = {v: k for k, v in vars(phonenumbers.ValidationResult).items() if isinstance(v, int) and k.isupper()}

# Minimal built-in dork set used only when data/phone_dorks.yaml cannot be read.
_FALLBACK_DORKS = {
    "social": [{"site": s, "intext": ["international", "e164", "raw_local"]}
               for s in ("facebook.com", "twitter.com", "linkedin.com", "instagram.com", "vk.com", "tiktok.com")],
    "individuals": [{"site": s, "intext": ["international", "e164", "raw_local"]}
                    for s in ("sync.me", "pastebin.com", "locatefamily.com")],
}


# --------------------------------------------------------------------------- parsing
def _candidates(raw: str, default_region: str | None) -> list:
    """Strings/regions to try, most specific first (mirrors phoneinfoga's '+'-prefixing)."""
    s = re.sub(r"^\s*tel:", "", raw.strip(), flags=re.I).strip()
    region = default_region.strip().upper() if default_region else None
    out: list = []
    if s.startswith("+"):
        out.append((s, region))
    elif re.match(r"^00\d", s):
        out.append(("+" + s[2:], region))
    else:
        if region:
            out.append((s, region))
            return out
        digits = re.sub(r"\D", "", s)
        if len(digits) >= 8:            # maybe the country code is included without "+"
            out.append(("+" + digits, None))
        if len(digits) >= 7:            # shorter strings are short codes; do not guess a country for them
            out.extend((s, r) for r in COMMON_REGIONS if r != region)
    return out


def _variants(info: dict) -> dict:
    """Named textual variants of a parsed number (used by dorks and ``formats``)."""
    e164, intl, national = info.get("e164"), info.get("international"), info.get("national")
    if not e164 or not national:
        return {}
    groups = re.findall(r"\d+", national)
    v = {
        "e164": e164,
        "international": intl or e164,
        "international_spaced": (intl or e164).replace("-", " "),
        "international_digits": e164[1:],
        "national": national,
        "raw_local": "".join(groups),
        "nsn": info.get("nsn") or phonenumbers.national_significant_number(phonenumbers.parse(e164)),
        "dashed": "-".join(groups),
        "dotted": ".".join(groups),
        "spaced": " ".join(groups),
    }
    if len(groups) >= 3:
        v["parenthesised"] = f"({groups[0]}) {'-'.join(groups[1:])}"
    return v


def _describe(n: phonenumbers.PhoneNumber, raw: str) -> dict:
    valid = phonenumbers.is_valid_number(n)
    fmt = lambda f: phonenumbers.format_number(n, f)  # noqa: E731
    info = {
        "raw": raw,
        "valid": valid,
        "possible": phonenumbers.is_possible_number(n),
        "e164": fmt(PhoneNumberFormat.E164),
        "international": fmt(PhoneNumberFormat.INTERNATIONAL),
        "national": fmt(PhoneNumberFormat.NATIONAL),
        "rfc3966": fmt(PhoneNumberFormat.RFC3966),
        "country_code": n.country_code,
        "region": phonenumbers.region_code_for_number(n),
        "country_name": geocoder.country_name_for_number(n, "en") or None,
        "location": geocoder.description_for_number(n, "en") or None,
        "carrier": carrier.name_for_number(n, "en") or None,
        "timezones": [t for t in timezone.time_zones_for_number(n) if t and t != "Etc/Unknown"],
        "number_type": _TYPE_NAMES.get(phonenumbers.number_type(n), "UNKNOWN"),
        "nsn": phonenumbers.national_significant_number(n),
    }
    if not valid:
        reason = phonenumbers.is_possible_number_with_reason(n)
        info["validation"] = ("possible length but not an assigned number" if reason == phonenumbers.ValidationResult.IS_POSSIBLE
                              else _VALIDATION_NAMES.get(reason, str(reason)))
    info["formats"] = list(dict.fromkeys(_variants(info).values()))
    return info


def parse_number(raw: str, default_region: str | None = None) -> dict:
    """Normalise a phone number offline.

    Returns a dict with ``valid``, ``possible``, ``e164``, ``international``,
    ``national``, ``rfc3966``, ``country_code``, ``region``, ``country_name``,
    ``location``, ``carrier``, ``timezones``, ``number_type``, ``nsn`` and
    ``formats`` (textual variants for dorking). With ``default_region`` only
    that region is used. Unprefixed inputs without a region may be inferred
    offline, but cannot authorize online lookups.
    Never raises: unparseable input yields ``{"valid": False, "error": ...}``.
    """
    if not isinstance(raw, str) or (default_region is not None and not isinstance(default_region, str)):
        return {"valid": False, "possible": False, "raw": "", "error": "phone and region must be strings", "formats": []}
    raw = raw.strip()
    if not raw:
        return {"valid": False, "possible": False, "raw": raw, "error": "empty input", "formats": []}
    best_possible = None
    try:
        for s, region in _candidates(raw, default_region):
            try:
                n = phonenumbers.parse(s, region)
            except NumberParseException:
                continue
            if phonenumbers.is_valid_number(n):
                return _with_input_scope(_describe(n, raw), raw, default_region)
            if best_possible is None and phonenumbers.is_possible_number(n):
                best_possible = n
        if best_possible is not None:
            return _with_input_scope(_describe(best_possible, raw), raw, default_region)
    except Exception as exc:  # noqa: BLE001 - defensive: never break a scan on odd input
        log.debug("parse_number(%r) failed", raw, exc_info=True)
        return {"valid": False, "possible": False, "raw": raw, "error": f"{type(exc).__name__}: {exc}", "formats": []}
    return {"valid": False, "possible": False, "raw": raw, "error": "not a parseable phone number", "formats": []}


def _with_input_scope(info: dict, raw: str, region: str | None) -> dict:
    supplied = re.sub(r"^\s*tel:", "", raw, flags=re.I).strip()
    info["online_allowed"] = bool(region and region.strip()) or supplied.startswith(("+", "00"))
    if not info["online_allowed"]:
        info["warning"] = "country was inferred offline; provide +country code or an explicit default region before online checks"
    return info


def _online_allowed(info: dict) -> bool:
    if not isinstance(info, dict) or not info.get("e164"):
        return False
    if "valid" in info and info["valid"] is not True:
        return False
    if "online_allowed" in info:
        return info["online_allowed"] is True
    raw = str(info.get("raw") or info["e164"]).strip()
    raw = re.sub(r"^tel:", "", raw, flags=re.I).strip()
    return raw.startswith(("+", "00"))


_PHONE_CHARS = re.compile(r"^\+?[\d\s().\-/]+$")
_ISO_DATE = re.compile(r"^\d{4}[-/.]\d{2}[-/.]\d{2}$")


def looks_like_phone(text: str) -> bool:
    """Cheap syntactic test: 7-15 digits with only phone punctuation (and not a date)."""
    s = re.sub(r"^\s*tel:", "", (text or "").strip(), flags=re.I).strip()
    if not s or _ISO_DATE.match(s) or not _PHONE_CHARS.match(s) or not re.match(r"^\+?\(?\d", s):
        return False
    digits = re.sub(r"\D", "", s)
    return 7 <= len(digits) <= 15 and len(set(digits)) > 1


# --------------------------------------------------------------------------- dorks
@lru_cache(maxsize=1)
def _load_dorks() -> dict:
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(DATA_FILE.read_text(encoding="utf-8")) or {}
        cats = data.get("categories") if isinstance(data.get("categories"), dict) else data
        return {k: [e for e in (v or []) if isinstance(e, dict)] for k, v in cats.items() if isinstance(v, list)}
    except Exception as exc:  # noqa: BLE001
        log.warning("phone dork list %s unavailable (%s); using built-in minimal set", DATA_FILE, exc)
        return _FALLBACK_DORKS


def _google(q: str) -> str:
    return "https://www.google.com/search?q=" + quote_plus(q)


def _quoted_or(terms: list) -> str:
    return " OR ".join(f'"{t}"' for t in dict.fromkeys(t for t in terms if t))


def _build_query(entry: dict, v: dict) -> str | None:
    parts = []
    sites = entry.get("sites") or ([entry["site"]] if entry.get("site") else [])
    if len(sites) == 1:
        parts.append(f"site:{sites[0]}")
    elif sites:
        parts.append("(" + " OR ".join(f"site:{s}" for s in sites) + ")")
    if entry.get("intitle"):
        parts.append(f'intitle:"{entry["intitle"]}"')
    terms = [f'"{v[k]}"' for k in dict.fromkeys(entry.get("intext") or []) if v.get(k)]
    terms += [f"inurl:{v[k]}" for k in dict.fromkeys(entry.get("inurl") or []) if v.get(k)]
    if not terms:
        return None
    parts.append(terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")")
    return " ".join(parts)


def _entry_label(entry: dict) -> str:
    if entry.get("label"):
        return str(entry["label"])
    sites = entry.get("sites") or ([entry["site"]] if entry.get("site") else [])
    return sites[0] if len(sites) == 1 else (f"{len(sites)} sites" if sites else str(entry.get("intitle") or "query"))


def tellows_url(info: dict) -> str | None:
    """Tellows page for the number: country domain + national digits, else tellows.com + E.164 digits."""
    v = _variants(info)
    if not v:
        return None
    domain = TELLOWS_DOMAINS.get(info.get("region") or "")
    if domain and domain != "tellows.com":
        return f"https://www.{domain}/num/{v['raw_local']}"
    return f"https://www.tellows.com/num/{v['international_digits']}"


def spamcalls_url(info: dict) -> str | None:
    v = _variants(info)
    return f"https://www.spamcalls.net/en/number/{v['international_digits']}" if v else None


def people_search(info: dict) -> list:
    """Direct reverse-lookup pages for US/CA numbers (Telespotter's site set)."""
    v = _variants(info)
    nsn = v.get("nsn", "")
    if info.get("region") not in ("US", "CA") or len(nsn) != 10:
        return []
    dashed = f"{nsn[:3]}-{nsn[3:6]}-{nsn[6:]}"
    links = [
        ("TruePeopleSearch", f"https://www.truepeoplesearch.com/resultphone?phoneno={nsn}"),
        ("FastPeopleSearch", f"https://www.fastpeoplesearch.com/{dashed}"),
        ("USPhoneBook", f"https://www.usphonebook.com/{dashed}"),
        ("ThatsThem", f"https://thatsthem.com/phone/{dashed}"),
        ("Whitepages", f"https://www.whitepages.com/phone/{v['international_digits']}"),
        ("sync.me", f"https://sync.me/search/?number={v['international_digits']}"),
        ("Spytox", f"https://www.spytox.com/reverse-phone-lookup/{dashed}"),
    ]
    return [{"category": "people-search", "label": label, "url": url, "engine": "direct", "query": None}
            for label, url in links]


def dorks(info: dict) -> list:
    """Categorised search URLs for a parsed number.

    Each item is ``{"category", "label", "url", "engine", "query"}`` with
    category in :data:`DORK_CATEGORIES`.  Returns ``[]`` when ``info`` has no
    usable number.
    """
    v = _variants(info)
    if not v:
        return []
    region = info.get("region")
    out: list = []
    cfg = _load_dorks()
    for category in ("social", "disposable", "reputation", "individuals"):
        for entry in cfg.get(category, []):
            regions = entry.get("regions")
            if regions and region not in [str(r).upper() for r in regions]:
                continue
            q = _build_query(entry, v)
            if q:
                out.append({"category": category, "label": _entry_label(entry), "url": _google(q), "engine": "google", "query": q})
    # direct reputation pages (Phunter / phoneintel / Moriarty sources)
    out.append({"category": "reputation", "label": "Tellows", "url": tellows_url(info), "engine": "direct", "query": None})
    if region == "GB":
        out.append({"category": "reputation", "label": "who-called.co.uk",
                    "url": f"https://who-called.co.uk/Number/{v['raw_local']}", "engine": "direct", "query": None})
    out.append({"category": "reputation", "label": "SpamCalls.net", "url": spamcalls_url(info), "engine": "direct", "query": None})
    # general search-engine queries (phoneinfoga "general" + Bing / DuckDuckGo / Yandex)
    general = _quoted_or([v["international"], v["e164"], v["raw_local"], v["national"]])
    docs = "(" + " OR ".join(f"ext:{e}" for e in DOC_EXTS) + ") (" + _quoted_or([v["international"], v["e164"], v["raw_local"]]) + ")"
    out += [
        {"category": "general", "label": "Google", "url": _google(general), "engine": "google", "query": general},
        {"category": "general", "label": "Google: documents", "url": _google(docs), "engine": "google", "query": docs},
        {"category": "general", "label": "Bing", "url": "https://www.bing.com/search?q=" + quote_plus(general), "engine": "bing", "query": general},
        {"category": "general", "label": "DuckDuckGo", "url": "https://duckduckgo.com/?q=" + quote_plus(general), "engine": "duckduckgo", "query": general},
        {"category": "general", "label": "Yandex", "url": "https://yandex.com/search/?text=" + quote_plus(general), "engine": "yandex", "query": general},
    ]
    out += people_search(info)
    return [d for d in out if d.get("url")]


# --------------------------------------------------------------------------- findings
def to_findings(info: dict, query: str) -> list:
    """Local analysis + one Finding per dork category, for uniform CLI/report output."""
    valid = bool(info.get("valid"))
    extra = {k: v for k, v in info.items() if k != "formats"}
    findings = [Finding(
        query=query, query_type=QUERY_TYPE, site="Number analysis", site_id="phone-local",
        status=Status.FOUND if valid else Status.NOT_FOUND, category="analysis", source=SOURCE,
        method="libphonenumber (offline)", extra=extra, error=info.get("error"),
    )]
    grouped: dict = {}
    for d in dorks(info):
        grouped.setdefault(d["category"], []).append(d)
    for category in DORK_CATEGORIES:
        items = grouped.get(category)
        if not items:
            continue
        findings.append(Finding(
            query=query, query_type=QUERY_TYPE, site=f"Suggested searches: {category}", site_id=f"phone-dorks-{category}",
            status=Status.UNKNOWN, category="dorks", tags=[category], source=SOURCE, method="search dork",
            url=items[0]["url"],
            extra={"urls": [d["url"] for d in items], "labels": [d["label"] for d in items], "count": len(items)},
        ))
    return findings


def _query_of(info: dict) -> str:
    return str(info.get("raw") or info.get("e164") or "")


def _classify(resp: Response) -> tuple:
    """(status, error) when a response is unusable (transport error, WAF, 429, 5xx), else (None, None)."""
    if resp.error:
        return Status.ERROR, resp.error
    err = detect_error_page(resp.text, resp.status)
    if err is None:
        return None, None
    if err.kind == "Rate limited":
        return Status.RATE_LIMITED, str(err)
    if err.kind == "Server":
        return Status.ERROR, str(err)
    return Status.BLOCKED, str(err)


def _changed_resource(requested: str, returned: str | None) -> bool:
    if not returned:
        return False
    try:
        before, after = urlsplit(requested), urlsplit(returned)
        return (before.hostname or "").removeprefix("www.") != (after.hostname or "").removeprefix("www.") or before.path.rstrip("/") != after.path.rstrip("/")
    except ValueError:
        return True


async def _guarded(fn: Callable[[], Awaitable[Finding]], base: dict, info: dict) -> Finding:
    if not _online_allowed(info):
        return Finding(status=Status.SKIPPED, error="online phone checks require +country code or an explicit default region", **base)
    try:
        return await fn()
    except Exception as exc:  # noqa: BLE001 - scrapers must never break a scan
        log.debug("%s failed", base.get("site_id"), exc_info=True)
        return Finding(status=Status.ERROR, error=f"{type(exc).__name__}: {exc}"[:300], **base)


# --------------------------------------------------------------------------- HTML helpers
def _html_lines(html: str) -> list:
    html = re.sub(r"(?is)<(script|style|noscript|svg).*?</\1>", " ", html)
    html = re.sub(r"(?i)</?(?:br|div|p|h[1-6]|section|article|li|ul|ol|tr|table|dl|dt|dd)\b[^>]*>", "\n", html)
    text = unescape(re.sub(r"<[^>]+>", " ", html))
    return [ln for ln in (re.sub(r"\s+", " ", ln).strip() for ln in text.split("\n")) if ln]


def _strip_tags(fragment: str) -> str:
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


_LABEL_LINE = re.compile(r"^[^\d:|]{2,40}:\s*$")


def _label_value(lines: list, labels: list) -> str | None:
    """Value of the first ``Label: value`` line (value may sit on the following line)."""
    for i, ln in enumerate(lines):
        for lab in labels:
            m = re.match(rf"^{re.escape(lab)}\s*:\s*(.*)$", ln, re.I)
            if not m:
                continue
            val = m.group(1).strip()
            if not val and i + 1 < len(lines) and not _LABEL_LINE.match(lines[i + 1]):
                val = lines[i + 1]
            return val or None
    return None


def _int(value: str | None) -> int | None:
    if not value:
        return None
    m = re.fullmatch(r"\s*([0-9]+|[0-9]{1,3}(?:[.,  ][0-9]{3})+)\s*", value)
    if not m:
        return None
    try:
        return int(re.sub(r"[^0-9]", "", m.group(1)))
    except ValueError:
        return None


# --------------------------------------------------------------------------- Tellows
_TELLOWS_LABELS = {
    "ratings": ["Ratings", "Rating", "Bewertungen", "Évaluations", "Evaluations", "Valoraciones", "Valutazioni",
                "Beoordelingen", "Avaliações", "Oceny", "Hodnocení", "Értékelések"],
    "comments": ["Comments", "Kommentare", "Commentaires", "Comentarios", "Commenti", "Reacties", "Comentários",
                 "Komentarze", "Komentáře", "Hozzászólások"],
    "searches": ["Search requests", "Searches", "Suchanfragen", "Recherches", "Búsquedas", "Ricerche",
                 "Zoekopdrachten", "Pesquisas", "Wyszukiwania"],
    "caller_type": ["Caller type", "Types of call", "Type of call", "Anrufertyp", "Type d'appel", "Tipo de llamada",
                    "Tipo di chiamata", "Type oproep", "Tipo de chamada", "Typ dzwoniącego"],
    "caller_name": ["Caller name", "Caller name / company", "Name des Anrufers", "Nom de l'appelant",
                    "Nombre del llamante", "Nome del chiamante"],
    "assessment": ["Assessment", "Einschätzung", "Évaluation", "Valoración", "Valutazione", "Beoordeling"],
    "activity": ["Activity", "Aktivität", "Activité", "Actividad", "Attività", "Activiteit"],
    "city": ["City", "Stadt", "Ville", "Ciudad", "Città", "Plaats", "Cidade", "Miasto"],
}
_TELLOWS_UNRATED = re.compile(
    r"not (?:been )?rated yet|noch nicht bewertet|pas encore été évalué|aún no ha sido valorado|non è ancora stato valutato", re.I)


_TELLOWS_PLACEHOLDERS = {"unknown", "unbekannt", "inconnu", "desconocido", "sconosciuto", "enter caller name",
                         "please choose...", "-"}


def _tellows_details(html: str) -> str:
    """The details card only (the rating form further down repeats the same labels with placeholder values)."""
    match = re.search(r'''<[a-z][^>]*\bid\s*=\s*(["'])details\1[^>]*>''', html, re.I)
    start = match.start() if match else 0
    end = min([i for i in (html.find('id="file_complaint"', start), html.find("<form", start)) if i >= start] or [len(html)])
    return html[start:end]


def parse_tellows(html: str) -> dict:
    """Extract the tellows score (1 trustworthy .. 9 untrustworthy), counts and caller info."""
    d: dict = {}
    m = (re.search(r'class="scoreimage"[^>]*?/score/s([0-9]{1,3})(?![0-9])', html)
         or re.search(r'alt="[^"]*?Score\s*([0-9]{1,3})(?![0-9])', html)
         or re.search(r"<title>[^<]*?score\s*:\s*([0-9]{1,3})(?![0-9])", html, re.I))
    if m:
        score = int(m.group(1))
        if 1 <= score <= 9:
            d["score"] = score
            d["score_max"] = 9
        else:
            d["_reputation_error"] = "Tellows score is outside its supported 1 to 9 range"
    t = re.search(r"<title>(.*?)</title>", html, re.S | re.I)
    if t:
        d["title"] = _strip_tags(t.group(1))
    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S | re.I)
    if h1:
        d["heading"] = _strip_tags(h1.group(1))
    lines = _html_lines(_tellows_details(html))
    for key, labels in _TELLOWS_LABELS.items():
        val = _label_value(lines, labels)
        if val is None or val.strip().lower() in _TELLOWS_PLACEHOLDERS:
            continue
        d[key] = _int(val) if key in ("ratings", "comments", "searches") else val
        if d[key] is None:
            d["_reputation_error"] = f"invalid {key} count for the queried number"
    if "ratings" not in d and d.get("title"):
        m = re.search(r"(\d+)\s*(?:ratings?|Bewertungen|évaluations|valoraciones|valutazioni)", d["title"], re.I)
        if m:
            d["ratings"] = int(m.group(1))
    unrated = bool(_TELLOWS_UNRATED.search(" ".join(lines[:200])))
    caller_type = (d.get("caller_type") or "").strip().lower()
    positive = bool(
        (d.get("ratings") or 0) > 0 or (d.get("comments") or 0) > 0
        or (d.get("score") is not None and d["score"] != 5)
        or (caller_type and caller_type not in ("unknown", "unbekannt", "inconnu", "desconocido", "sconosciuto"))
    )
    counts = [d[key] for key in ("ratings", "comments") if d.get(key) is not None]
    negative = unrated or (not positive and bool(counts) and all(value == 0 for value in counts))
    d["reported"] = None if positive == negative else positive
    if positive and negative:
        d["_reputation_error"] = "positive reputation evidence conflicts with an explicit no-reports statement"
    return d


async def _tellows(info: dict, http: Http, impersonate: bool) -> Finding:
    url = tellows_url(info)
    base = dict(query=_query_of(info), query_type=QUERY_TYPE, site="Tellows", site_id="phone-tellows",
                category="reputation", source=SOURCE, url=url, method="scrape")

    async def run() -> Finding:
        resp = await http.get(url, headers=_HTML_ACCEPT, impersonate=impersonate)
        st, err = _classify(resp)
        common = dict(http_status=resp.status or None, elapsed=round(resp.elapsed, 3))
        if st:
            return Finding(status=st, error=err, **common, **base)
        if _changed_resource(url, resp.url):
            return Finding(status=Status.UNKNOWN, error="response redirected to a different resource", **common, **base)
        if resp.status == 404:
            return Finding(status=Status.NOT_FOUND, extra={"reported": False}, **common, **base)
        if resp.status != 200:
            return Finding(status=Status.UNKNOWN, error=f"HTTP {resp.status}", **common, **base)
        page = evidence_page(resp.text, info["e164"], info.get("region"), resp.url or url)
        if page.error:
            return Finding(status=Status.UNKNOWN, error=page.error, **common, **base)
        data = parse_tellows(page.html)
        if data.get("reported") is None or data.get("_reputation_error"):
            return Finding(status=Status.UNKNOWN, extra=data,
                           error=data.get("_reputation_error", "no explicit reputation verdict in the numbered page"), **common, **base)
        data["domain"] = re.sub(r"^https?://(www\.)?([^/]+).*$", r"\2", resp.url or url)
        base["url"] = resp.url or url
        return Finding(status=Status.FOUND if data["reported"] else Status.NOT_FOUND, extra=data, **common, **base)

    return await _guarded(run, base, info)


# --------------------------------------------------------------------------- SpamCalls
_SPAMCALLS_GONE = re.compile(r"(?:user )?reports for (?:the|this) phone number are (?:not \(no longer\)|no longer|not) available", re.I)


def parse_spamcalls(html: str) -> dict:
    """Extract rating / caller type / explanation from a spamcalls.net number page."""
    d: dict = {}
    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S | re.I)
    if h1:
        d["heading"] = _strip_tags(h1.group(1))
    for key, anchor in (("rating", "ratings"), ("caller_type", "estimates"), ("explanation", "solution")):
        m = re.search(rf'<a[^>]+href="#{anchor}"[^>]*>(.*?)</a>', html, re.S | re.I)
        if m and _strip_tags(m.group(1)):
            d[key] = _strip_tags(m.group(1))
    text = " ".join(_html_lines(html))
    m = _review_count(html)
    if m:
        d["reports"] = _int(m.group(1))
        if d["reports"] is None:
            d["_reputation_error"] = "invalid report count for the queried number"
    positive = any(d.get(k) for k in ("reports", "rating", "caller_type"))
    negative = bool(_SPAMCALLS_GONE.search(text)) or d.get("reports") == 0
    if negative and not positive:
        return {"reported": False, "reports": 0}
    d["reported"] = True if positive and not negative else None
    if positive and negative:
        d["_reputation_error"] = "positive reputation evidence conflicts with an explicit no-reports statement"
    return d


async def _spamcalls(info: dict, http: Http, impersonate: bool) -> Finding:
    url = spamcalls_url(info)
    base = dict(query=_query_of(info), query_type=QUERY_TYPE, site="SpamCalls", site_id="phone-spamcalls",
                category="reputation", source=SOURCE, url=url, method="scrape")

    async def run() -> Finding:
        resp = await http.get(url, headers=_HTML_ACCEPT, impersonate=impersonate)
        st, err = _classify(resp)
        common = dict(http_status=resp.status or None, elapsed=round(resp.elapsed, 3))
        if st:
            return Finding(status=st, error=err, **common, **base)
        if _changed_resource(url, resp.url):
            return Finding(status=Status.UNKNOWN, error="response redirected to a different resource", **common, **base)
        base["url"] = resp.url or url
        if resp.status in (404, 410):
            return Finding(status=Status.NOT_FOUND, extra={"reported": False, "reports": 0}, **common, **base)
        if resp.status != 200:
            return Finding(status=Status.UNKNOWN, error=f"HTTP {resp.status}", **common, **base)
        page = evidence_page(resp.text, info["e164"], info.get("region"), resp.url or url)
        data = parse_spamcalls(page.html)
        return _reputation_finding(data, page.ratings, page.error, common, base)

    return await _guarded(run, base, info)


# --------------------------------------------------------------------------- ShouldIAnswer / CleverDialer
_REVIEW_RE = re.compile(r"(?<![0-9.,+-])([+-]?[0-9][0-9.,]*)\s*(?:user\s+)?(?:reports?|ratings?|reviews?|comments?|complaints?|bewertunge?n?|kommentare?)\b", re.I)
_NO_REPORTS_RE = re.compile(
    r"(?:no (?:reviews?|ratings?|reports?|comments?)(?: yet| for (?:this|the) (?:phone )?number)?"
    r"|(?:this|the) (?:phone )?number has not been rated(?: yet)?"
    r"|keine (?:bewertunge?n?|kommentare?)(?: für diese Nummer)?"
    r"|(?:diese Nummer wurde )?noch nicht bewertet)[.!]?", re.I)


def _review_count(html: str):
    # Never join a number heading to the words "user reports" in the next block.
    html = re.sub(r"(?is)<(h1|title)\b[^>]*>.*?</\1>", "", html)
    return next((m for line in _html_lines(html) if (m := _REVIEW_RE.search(line))), None)


def _reputation_finding(data: dict, ratings: dict, error: str | None, common: dict, base: dict) -> Finding:
    data.update(ratings)
    counts = [ratings[key] for key in ("rating_count", "review_count") if key in ratings]
    structured = any(value > 0 for value in counts) if counts else None
    reported = data.get("reported")
    error = error or data.get("_reputation_error")
    if structured is not None and reported is not None and structured != reported:
        error = "structured ratings conflict with the numbered page's reputation verdict"
    if reported is None:
        reported = structured
    data["reported"] = None if error else reported
    if error or reported is None:
        return Finding(status=Status.UNKNOWN, extra=data,
                       error=error or "no explicit reputation evidence for the queried number", **common, **base)
    return Finding(status=Status.FOUND if reported else Status.NOT_FOUND, extra=data, **common, **base)


def _review_details(html: str, *, assessment: bool = False) -> dict:
    lines = _html_lines(html)
    extra: dict = {}
    if assessment:
        value = _label_value(lines, ["Assessment", "Rating", "Bewertung"]) or ""
        rating = re.fullmatch(r"(Positive|Neutral|Negative|Dangerous)", value, re.I)
        if rating:
            extra["assessment"] = rating.group(1)
    match = _review_count(html)
    if match:
        extra["reviews"] = _int(match.group(1))
        if extra["reviews"] is None:
            extra["_reputation_error"] = "invalid review count for the queried number"
    positive = bool(extra.get("assessment") or extra.get("reviews"))
    negative = any(_NO_REPORTS_RE.fullmatch(line) for line in lines) or extra.get("reviews") == 0
    extra["reported"] = None if positive == negative else positive
    if positive and negative:
        extra["_reputation_error"] = "positive reputation evidence conflicts with an explicit no-reports statement"
    return extra


async def _shouldianswer(info: dict, http: Http, impersonate: bool) -> Finding:
    digits = info["e164"][1:]
    url = f"https://www.shouldianswer.com/phone-number/{digits}"
    base = dict(query=_query_of(info), query_type=QUERY_TYPE, site="ShouldIAnswer", site_id="phone-shouldianswer",
                category="reputation", source=SOURCE, url=url, method="scrape")

    async def run() -> Finding:
        resp = await http.get(url, headers=_HTML_ACCEPT, impersonate=impersonate)
        st, err = _classify(resp)
        common = dict(http_status=resp.status or None, elapsed=round(resp.elapsed, 3))
        if st:
            return Finding(status=st, error=err, **common, **base)
        if _changed_resource(url, resp.url):
            return Finding(status=Status.UNKNOWN, error="response redirected to a different resource", **common, **base)
        base["url"] = resp.url or url
        if resp.status == 404:
            return Finding(status=Status.NOT_FOUND, extra={"reported": False}, **common, **base)
        if resp.status != 200:
            return Finding(status=Status.UNKNOWN, error=f"HTTP {resp.status}", **common, **base)
        page = evidence_page(resp.text, info["e164"], info.get("region"), resp.url or url)
        return _reputation_finding(_review_details(page.html, assessment=True), page.ratings, page.error, common, base)

    return await _guarded(run, base, info)


async def _cleverdialer(info: dict, http: Http, impersonate: bool) -> Finding:
    digits = info["e164"][1:]
    region = info.get("region") or ""
    url = (f"https://www.cleverdialer.de/nummer/{digits}" if region == "DE"
           else f"https://www.cleverdialer.com/phone/{digits}")
    base = dict(query=_query_of(info), query_type=QUERY_TYPE, site="CleverDialer", site_id="phone-cleverdialer",
                category="reputation", source=SOURCE, url=url, method="scrape")

    async def run() -> Finding:
        resp = await http.get(url, headers=_HTML_ACCEPT, impersonate=impersonate)
        st, err = _classify(resp)
        common = dict(http_status=resp.status or None, elapsed=round(resp.elapsed, 3))
        if st:
            return Finding(status=st, error=err, **common, **base)
        if _changed_resource(url, resp.url):
            return Finding(status=Status.UNKNOWN, error="response redirected to a different resource", **common, **base)
        base["url"] = resp.url or url
        if resp.status == 404:
            return Finding(status=Status.NOT_FOUND, extra={"reported": False}, **common, **base)
        if resp.status != 200:
            return Finding(status=Status.UNKNOWN, error=f"HTTP {resp.status}", **common, **base)
        page = evidence_page(resp.text, info["e164"], info.get("region"), resp.url or url)
        return _reputation_finding(_review_details(page.html), page.ratings, page.error, common, base)

    return await _guarded(run, base, info)


async def reputation(info: dict, http: Http, *, impersonate: bool = True, selected: set[str] | None = None) -> list:
    """Keyless reputation lookups (Tellows, SpamCalls, ShouldIAnswer, CleverDialer).  Never raises."""
    if not _online_allowed(info):
        return []
    checks = {"phone-tellows": _tellows, "phone-spamcalls": _spamcalls,
              "phone-shouldianswer": _shouldianswer, "phone-cleverdialer": _cleverdialer}
    return list(await asyncio.gather(*(check(info, http, impersonate) for ident, check in checks.items()
                                       if selected is None or ident in selected)))


# --------------------------------------------------------------------------- keyed / API providers
def _json(resp: Response):
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


def _api_error(resp: Response, data) -> tuple:
    """(status, message) for failed API calls, else (None, None)."""
    if resp.error:
        return Status.ERROR, resp.error
    if resp.status == 429:
        return Status.RATE_LIMITED, "HTTP 429"
    msg = None
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            msg = err.get("info") or err.get("message") or err.get("type") or json.dumps(err)[:200]
        elif err:
            msg = str(err)
        elif data.get("message") and resp.status >= 400:
            msg = str(data["message"])
    if msg or resp.status >= 400:
        return Status.ERROR, msg or f"HTTP {resp.status}"
    if resp.status != 200:
        return Status.UNKNOWN, f"unexpected HTTP {resp.status}"
    if data is None:
        return Status.ERROR, "non-JSON response"
    return None, None


def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def _returned_phone_issue(info: dict, fields: dict) -> str | None:
    """Reject conflicting echoes; an omitted optional echo is not invented."""
    for name, value in fields.items():
        if name in ("international_format", "format.international") and (value is None or value == ""):
            continue
        if not isinstance(value, str):
            return f"invalid returned phone identifier: {name}"
        compact = re.sub(r"[ ().-]", "", value)
        if compact.startswith("00"):
            compact = "+" + compact[2:]
        if not re.fullmatch(r"\+?[0-9]+", compact):
            return f"invalid returned phone identifier: {name}"
        if compact.lstrip("+") != info["e164"].lstrip("+"):
            return f"returned phone identifier differs from the query: {name}"
    return None


async def _numverify(info: dict, http: Http, key: str) -> Finding:
    base = dict(query=_query_of(info), query_type=QUERY_TYPE, site="Numverify", site_id="phone-numverify",
                category="validation", source=SOURCE, url="https://numverify.com/", method="api")

    async def run() -> Finding:
        url = "https://apilayer.net/api/validate?" + urlencode({"access_key": key, "number": info["e164"][1:], "format": 1})
        resp = await http.get(url, headers=_JSON_ACCEPT)
        data = _json(resp)
        st, err = _api_error(resp, data)
        common = dict(http_status=resp.status or None, elapsed=round(resp.elapsed, 3))
        if st:
            return Finding(status=st, error=err, **common, **base)
        if not isinstance(data, dict):
            return Finding(status=Status.UNKNOWN, error="expected a validation object", **common, **base)
        issue = _returned_phone_issue(info, {k: data[k] for k in ("number", "international_format") if k in data})
        if issue:
            return Finding(status=Status.UNKNOWN, error=issue, **common, **base)
        keys = ("valid", "number", "local_format", "international_format", "country_prefix", "country_code",
                "country_name", "location", "carrier", "line_type")
        extra = _clean({k: data.get(k) for k in keys})
        if type(data.get("valid")) is not bool:
            return Finding(status=Status.UNKNOWN, error="missing or invalid validation evidence", **common, **base)
        extra["valid"] = data["valid"]
        return Finding(status=Status.FOUND if extra["valid"] else Status.NOT_FOUND, extra=extra, **common, **base)

    return await _guarded(run, base, info)


def _parse_abstractapi(data: dict) -> dict:
    if "phone_validation" in data or "phone_carrier" in data:      # Phone Intelligence product
        val, car = data.get("phone_validation") or {}, data.get("phone_carrier") or {}
        loc, risk = data.get("phone_location") or {}, data.get("phone_risk") or {}
        return _clean({
            "valid": val.get("is_valid"), "line_status": val.get("line_status"), "voip": val.get("is_voip"),
            "carrier": car.get("name"), "line_type": car.get("line_type"),
            "location": ", ".join(p for p in (loc.get("city"), loc.get("region")) if p) or None,
            "country_name": loc.get("country_name"), "country_code": loc.get("country_code"),
            "risk_level": risk.get("risk_level"), "disposable": risk.get("is_disposable"),
            "abuse_detected": risk.get("is_abuse_detected"),
        })
    fmt, country = data.get("format") or {}, data.get("country") or {}      # Phone Validation product
    return _clean({
        "valid": data.get("valid"), "carrier": data.get("carrier"), "line_type": data.get("type"),
        "location": data.get("location"), "country_name": country.get("name"), "country_code": country.get("code"),
        "country_prefix": country.get("prefix"), "international_format": fmt.get("international"),
        "local_format": fmt.get("local"),
    })


async def _abstractapi(info: dict, http: Http, key: str) -> Finding:
    base = dict(query=_query_of(info), query_type=QUERY_TYPE, site="AbstractAPI", site_id="phone-abstractapi",
                category="validation", source=SOURCE, url="https://www.abstractapi.com/phone-validation-api", method="api")

    async def run() -> Finding:
        url = "https://phonevalidation.abstractapi.com/v1/?" + urlencode({"api_key": key, "phone": info["e164"][1:]})
        resp = await http.get(url, headers=_JSON_ACCEPT)
        data = _json(resp)
        st, err = _api_error(resp, data)
        common = dict(http_status=resp.status or None, elapsed=round(resp.elapsed, 3))
        if st:
            return Finding(status=st, error=err, **common, **base)
        if not isinstance(data, dict):
            return Finding(status=Status.UNKNOWN, error="expected a validation object", **common, **base)
        identifiers = {"phone": data["phone"]} if "phone" in data else {}
        if isinstance(data.get("format"), dict) and "international" in data["format"]:
            identifiers["format.international"] = data["format"]["international"]
        issue = _returned_phone_issue(info, identifiers)
        if issue:
            return Finding(status=Status.UNKNOWN, error=issue, **common, **base)
        extra = _parse_abstractapi(data if isinstance(data, dict) else {})
        if type(extra.get("valid")) is not bool:
            return Finding(status=Status.UNKNOWN, error="missing or invalid validation evidence", **common, **base)
        return Finding(status=Status.FOUND if extra["valid"] else Status.NOT_FOUND, extra=extra, **common, **base)

    return await _guarded(run, base, info)


_OVH_CACHE: dict = {}


async def _ovh(info: dict, http: Http) -> Finding:
    """Match a listed geographic zone; this does not identify a current carrier."""
    country = str(info.get("region") or "").lower()
    url = f"https://api.ovh.com/1.0/telephony/number/detailedZones?country={country}"
    base = dict(query=_query_of(info), query_type=QUERY_TYPE, site="OVH Telecom", site_id="phone-ovh",
                category="carrier", source=SOURCE, url=url, method="api")

    async def run() -> Finding:
        zones = _OVH_CACHE.get(country)
        common: dict = {}
        if zones is None:
            resp = await http.get(url, headers=_JSON_ACCEPT)
            data = _json(resp)
            st, err = _api_error(resp, data)
            common = dict(http_status=resp.status or None, elapsed=round(resp.elapsed, 3))
            if st:
                return Finding(status=st, error=err, **common, **base)
            if not isinstance(data, list):
                return Finding(status=Status.ERROR, error="unexpected response", **common, **base)
            if any(not isinstance(zone, dict) or not isinstance(zone.get("number"), str)
                   or len(zone["number"]) > 15 or not re.fullmatch(r"[0-9]+x*", zone["number"])
                   or ("country" in zone and zone["country"] != country) for zone in data):
                return Finding(status=Status.UNKNOWN, error="missing or malformed number-range evidence", **common, **base)
            zones = _OVH_CACHE[country] = data
        raw_local = _variants(info).get("raw_local", "")
        if len(raw_local) <= 6:
            return Finding(status=Status.UNKNOWN, error="number too short for a zone match", **common, **base)
        # Use the returned mask's prefix and length. A fixed six-digit prefix
        # plus four wildcards silently maps eleven-digit national numbers to a
        # different ten-digit range and misses valid ranges of other sizes.
        hit = next((z for z in zones if re.fullmatch(z["number"].replace("x", "[0-9]"), raw_local)), None)
        if hit is None:
            return Finding(status=Status.NOT_FOUND, extra={"_requested_national_number": raw_local}, **common, **base)
        extra = _clean({"number_range": hit.get("number"), "city": hit.get("city"), "zip_code": hit.get("zipCode"),
                        "zone_type": hit.get("type"), "zones": hit.get("zneList"),
                        "international_number": hit.get("internationalNumber")})
        return Finding(status=Status.FOUND, extra=extra, **common, **base)

    return await _guarded(run, base, info)


async def _google_cse(info: dict, http: Http, key: str, cx: str) -> Finding:
    """phoneinfoga's googlecse scanner: run the general dork through Google Custom Search."""
    v = _variants(info)
    q = _quoted_or([v["international"], v["e164"], v["raw_local"], v["national"]])
    base = dict(query=_query_of(info), query_type=QUERY_TYPE, site="Google CSE", site_id="phone-googlecse",
                category="search", source=SOURCE, url=_google(q), method="api")

    async def run() -> Finding:
        url = "https://www.googleapis.com/customsearch/v1?" + urlencode({"key": key, "cx": cx, "q": q, "num": 10})
        resp = await http.get(url, headers=_JSON_ACCEPT)
        data = _json(resp)
        st, err = _api_error(resp, data)
        common = dict(http_status=resp.status or None, elapsed=round(resp.elapsed, 3))
        if st:
            return Finding(status=st, error=err, **common, **base)
        if not isinstance(data, dict):
            return Finding(status=Status.UNKNOWN, error="expected a search response object", **common, **base)
        meta = data.get("searchInformation")
        total_text = meta.get("totalResults") if isinstance(meta, dict) else None
        if not isinstance(total_text, str) or not re.fullmatch(r"[0-9]{1,30}", total_text):
            return Finding(status=Status.UNKNOWN, error="missing or invalid search total", **common, **base)
        total = int(total_text)
        items = data.get("items", [])
        if not isinstance(items, list):
            return Finding(status=Status.UNKNOWN, error="invalid search results collection", **common, **base)
        from .reports import _safe_http_url

        results = []
        malformed = False
        for item in items:
            if (not isinstance(item, dict) or not _safe_http_url(item.get("link"))
                    or any(k in item and not isinstance(item[k], str) for k in ("title", "snippet"))):
                malformed = True
                continue
            results.append(_clean({"title": item.get("title"), "url": item["link"], "snippet": item.get("snippet")}))
        extra = {"query": q, "total": total, "results": results}
        if malformed or bool(total) != bool(results):
            return Finding(status=Status.UNKNOWN, error="incomplete or contradictory search evidence", extra=extra, **common, **base)
        return Finding(status=Status.FOUND if results else Status.NOT_FOUND, extra=extra, **common, **base)

    return await _guarded(run, base, info)


async def api_lookups(info: dict, http: Http, *, selected: set[str] | None = None) -> list:
    """Keyed providers (numverify, AbstractAPI, Google CSE) when configured, plus keyless OVH for FR/BE/GB/ES/CH."""
    if not _online_allowed(info):
        return []
    tasks = []
    numverify_key, abstract_key = get_key("numverify"), get_key("abstractapi")
    cse_key, cse_cx = get_key("google_cse_key"), get_key("google_cse_cx")
    if numverify_key and (selected is None or "phone-numverify" in selected):
        tasks.append(_numverify(info, http, numverify_key))
    if abstract_key and (selected is None or "phone-abstractapi" in selected):
        tasks.append(_abstractapi(info, http, abstract_key))
    if info.get("region") in OVH_REGIONS and (selected is None or "phone-ovh" in selected):
        tasks.append(_ovh(info, http))
    if cse_key and cse_cx and (selected is None or "phone-googlecse" in selected):
        tasks.append(_google_cse(info, http, cse_key, cse_cx))
    return list(await asyncio.gather(*tasks)) if tasks else []


# --------------------------------------------------------------------------- orchestration
async def scan(query: str, http: Http | None = None, *, default_region: str | None = None,
               online: bool = True, apis: bool = True, impersonate: bool = True) -> list:
    """Full phone workflow: offline analysis + dorks, then reputation and API lookups when ``online``."""
    info = parse_number(query, default_region)
    findings = to_findings(info, query)
    if online and http is not None and _online_allowed(info):
        rep, api = await asyncio.gather(reputation(info, http, impersonate=impersonate),
                                        api_lookups(info, http) if apis else asyncio.sleep(0, result=[]))
        findings += rep + api
    return findings


__all__ = [
    "parse_number", "dorks", "people_search", "reputation", "api_lookups", "to_findings", "looks_like_phone", "scan",
    "parse_tellows", "parse_spamcalls", "tellows_url", "spamcalls_url", "DORK_CATEGORIES", "TELLOWS_DOMAINS", "OVH_REGIONS",
]
