"""Read-only comparison of returned profile details, with explicit query boundaries.

Repetition is a lead, not an identity verdict. Never changes findings or scores,
runs requests, infers usernames from emails, or compares background analysis.
"""
from __future__ import annotations

import re
import unicodedata
from collections import defaultdict

from .models import INFO_CATEGORIES, Status
from .modules import _service_host, finding_service_key
from .presentation import assessment, split_fields

EXPLANATION = (
    "Counts describe distinct sites returning a value or word, not repeated mentions or adapters. "
    "Open the evidence to check the original fields. Shared details and shared sites are leads, "
    "not proof that accounts belong to the same person."
)
SCOPE = (
    "Compares returned names, usernames, biography text, contact details, locations and organizations. "
    "Background analysis, checking flags, counters, URLs, generic page titles/descriptions and "
    "exact query echoes are excluded. Word matching uses words of at least three letters and an "
    "English list of common words to ignore; it does not translate text or infer identity. "
    "Queries retain their exact recorded text, including case; distinct queries do not necessarily "
    "refer to distinct accounts or people. Sites are grouped by their recorded provider or app identity, "
    "falling back to the result URL host or site name. Checks identified only by a shared API host "
    "are excluded from comparisons because their provider identity is unresolved. "
    "Recognized fields are inspected up to six levels deep, with at most 64 fields per result and "
    "4,096 characters per field."
)
_ALIASES = {
    "name": "Name", "fullname": "Name", "displayname": "Name", "realname": "Name",
    "firstname": "Given name", "givenname": "Given name", "lastname": "Family name", "surname": "Family name",
    "username": "Username", "login": "Username", "handle": "Username", "nickname": "Nickname",
    "bio": "Biography", "biography": "Biography", "about": "Biography", "aboutme": "Biography",
    "email": "Email", "emails": "Email", "emailaddress": "Email", "publicemail": "Email",
    "phone": "Phone", "phones": "Phone", "phonenumber": "Phone", "mobile": "Phone", "mobilenumber": "Phone",
    "location": "Location", "city": "City", "country": "Country", "region": "Region",
    "company": "Organization", "organization": "Organization", "employer": "Organization",
    "occupation": "Occupation", "school": "School",
}
_WORDS = {"Name", "Given name", "Family name", "Nickname", "Biography", "Organization", "Occupation"}
_VARIATIONS = {"Name", "Given name", "Family name", "Location", "City", "Country", "Organization"}
_STOP = frozenset("""
    a an and are as at be been being but by can could did do does for from had has have
    he her here hers him his how i if in into is it its just me more most my no nor not
    of on or our ours out she so some than that the their theirs them then there these
    they this those through to too us very was we were what when where which who why
    will with would you your yours about account accounts avatar bio click com copyright
    create email false follow followers following home http https join login member name
    none null official online page password privacy profile registered sign signup site
    terms true unknown user users verified website welcome www redacted unavailable
""".split())
_EMPTY = {"unknown", "none", "null", "n/a", "not available", "not found", "redacted", "hidden", "private"}
_URL = re.compile(r"https?://\S+|[^\s@]+@[^\s@]+\.[^\s@]+", re.I)
_WORD = re.compile(r"[^\W\d_]{3,}", re.UNICODE)
_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
TEXT_LIMIT = 4096
FIELD_LIMIT = 64
PATTERN_LIMIT = 100
EVIDENCE_LIMIT = 40


def _normal(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _identity(query: str, kind: str) -> tuple[str, str]:
    return query, kind


def _site_key(f) -> str | None:
    return finding_service_key(f, fallback=_normal(f.site or f.site_id))


def _value_normal(family, value):
    text = _normal(value)
    return re.sub(r"[\s().-]", "", text) if family == "Phone" else text


def _strings(value, path=(), depth=0):
    if depth > 6:
        return
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            if not str(key).startswith("_"):
                yield from _strings(child, (*path, str(key)), depth + 1)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from _strings(child, (*path, str(i)), depth + 1)


def _family(path) -> str | None:
    # Container names such as "others" may already be part of a flattened key.
    for key in reversed(path):
        if key.isdigit():
            continue
        name = re.sub(r"[^a-z]", "", key.split(".")[-1].lower())
        return _ALIASES.get(name)
    return None


def _entries(findings):
    entries, truncated = [], False
    for f in findings:
        if f.status is not Status.FOUND or f.category in INFO_CATEGORIES:
            continue
        site_key = _site_key(f)
        if site_key is None:
            continue
        identity = _identity(f.query, f.query_type)
        used = 0
        for path, raw in _strings(split_fields(f.extra)[0]):
            family = _family(path)
            if family is None:
                continue
            value = " ".join(_CONTROLS.sub(" ", raw).split())
            normal = _value_normal(family, value)
            if (not normal or normal in _EMPTY or "[redacted]" in normal or "\ufffd" in value
                    or normal.startswith(("[unsupported ", "[circular", "[truncated", "[maximum depth]"))
                    or not any(c.isalnum() for c in normal)
                    or (family == "Phone" and sum(c.isdigit() for c in normal) < 7)
                    or normal == _value_normal(family, f.query) or normal.startswith(("http://", "https://", "www."))
                    or (family in {"Email", "Phone"} and any(c in value for c in "*•…"))):
                continue
            if used >= FIELD_LIMIT:
                truncated = True
                break
            used += 1
            if len(value) > TEXT_LIMIT:
                truncated = True
                value = value[:TEXT_LIMIT]
            entries.append({"family": family, "value": value, "normal": _value_normal(family, value),
                            "site_key": site_key, "identity": identity, "query": f.query,
                            "query_type": f.query_type, "site": f.site, "site_id": f.site_id,
                            "url": f.url, "field": ".".join(path),
                            "needs_review": assessment(f)[0] == "Needs review"})
    return entries, truncated


def _evidence(entries):
    from .reports import _safe_http_url

    seen, output = set(), []
    for entry in entries:
        key = (entry["identity"], entry["site_id"], entry["field"], entry["value"])
        if key in seen:
            continue
        seen.add(key)
        record = {k: entry[k] for k in ("query", "query_type", "site", "site_id",
                                       "field", "value", "needs_review")}
        record["url"] = _safe_http_url(entry["url"])
        output.append(record)
    output.sort(key=lambda e: (e["query"].casefold(), e["query_type"], e["site"].casefold(), e["field"], e["value"]))
    return output[:EVIDENCE_LIMIT], max(0, len(output) - EVIDENCE_LIMIT)


def _record(kind, field, value, entries):
    evidence, omitted = _evidence(entries)
    return {"kind": kind, "field": field, "value": value,
            "site_count": len({e["site_key"] for e in entries}),
            "query_count": len({e["identity"] for e in entries}),
            "evidence": evidence, "omitted_evidence": omitted,
            "needs_review": any(e["needs_review"] for e in entries)}


def compare_details(findings, *, across_queries=False) -> dict:
    """Common values/words and visible variations, using bounded recognized fields."""
    entries, truncated = _entries(findings)
    values, words, families = defaultdict(list), defaultdict(list), defaultdict(list)
    for entry in entries:
        family, value = entry["family"], entry["normal"]
        if family != "Biography" and len(value) <= 160:
            values[(family, value)].append(entry)
            families[family].append(entry)
        if family in _WORDS:
            plain = re.sub(r"<[^>]*>", " ", _URL.sub(" ", value))
            tokens = set(_WORD.findall(plain)) - _STOP
            for token in tokens:
                words[token].append(entry)

    def qualifies(group):
        if across_queries:
            return len({e["identity"] for e in group}) >= 2
        return len({e["site_key"] for e in group}) >= 2

    common = []
    exact_coverage = []
    for (family, _), group in values.items():
        if qualifies(group):
            common.append(_record("value", family, min(e["value"] for e in group), group))
            if family in _WORDS:
                exact_coverage.append((set(_WORD.findall(group[0]["normal"])),
                                       {(e["site_key"], e["identity"]) for e in group}))
    for word, group in words.items():
        coverage = {(e["site_key"], e["identity"]) for e in group}
        # Prefer the complete repeated name over redundant rows for each of its words.
        if qualifies(group) and not any(word in tokens and coverage == exact for tokens, exact in exact_coverage):
            common.append(_record("word", "Profile word", word, group))
    common.sort(key=lambda r: (-r["query_count"] if across_queries else 0, -r["site_count"],
                               r["kind"] != "value", r["field"], _normal(r["value"])))

    variations = []
    for family, group in families.items():
        distinct = {e["normal"] for e in group}
        if family not in _VARIATIONS or len(distinct) < 2 or not qualifies(group):
            continue
        grouped = defaultdict(list)
        for entry in group:
            grouped[entry["normal"]].append(entry)
        variants = [_record("value", family, min(e["value"] for e in rows), rows)
                    for rows in grouped.values()]
        variants.sort(key=lambda r: (-r["site_count"], _normal(r["value"])))
        variations.append({"field": family, "values": variants[:20], "omitted_values": max(0, len(variants) - 20)})

    return {"common": common[:PATTERN_LIMIT], "omitted_patterns": max(0, len(common) - PATTERN_LIMIT),
            "variations": sorted(variations, key=lambda v: v["field"]), "truncated_input": truncated,
            "compared_sites": len({e["site_key"] for e in entries}), "compared_fields": len(entries),
            "query_count": len({e["identity"] for e in entries}), "across_queries": across_queries}


def shared_sites(findings) -> list:
    groups = defaultdict(list)
    for f in findings:
        if f.status is Status.FOUND and f.category not in INFO_CATEGORIES:
            host = _site_key(f)
            if host is None:
                continue
            groups[host].append(f)
    output = []
    for host, rows in groups.items():
        queries = {}
        for f in rows:
            queries.setdefault(_identity(f.query, f.query_type), {"query": f.query, "query_type": f.query_type})
        if len(queries) >= 2:
            display_host = _service_host(rows[0].extra.get("_service_host")) or _service_host(rows[0].url) or host
            output.append({"site": rows[0].site, "host": display_host, "query_count": len(queries),
                           "queries": sorted(queries.values(), key=lambda q: (q["query"], q["query_type"]))})
    return sorted(output, key=lambda r: (-r["query_count"], r["site"].casefold()))


def comparisons(summary) -> dict:
    """Per-query comparisons always; cross-query comparisons only with explicit opt-in."""
    from .reports import group_by_query

    per_query = [{"query": v.query, "query_type": v.query_type, **compare_details(v.findings)}
                 for v in group_by_query(summary)]
    enabled = (summary.options or {}).get("compare_queries") is True
    return {"per_query": per_query,
            "across_queries": compare_details(summary.findings, across_queries=True) if enabled else None,
            "shared_sites": shared_sites(summary.findings) if enabled else [],
            "explanation": EXPLANATION, "scope": SCOPE}
