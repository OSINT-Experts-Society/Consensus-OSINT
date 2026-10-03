"""Confidence scoring for FOUND findings (0..1).

Combines: how strict the detection rule is, whether metadata was scraped,
agreement between several data sources, and cross-profile name consensus
(idea from user-scanner's confidence module).
"""
from __future__ import annotations

import math
import unicodedata
from collections import Counter
from collections.abc import Iterable

from .models import INFO_CATEGORIES, Finding, Status
from .presentation import enrichment_fields
from .sitesdb import Site

NAME_KEYS = ("fullname", "name", "display_name", "displayname", "real_name")


def base_confidence(f: Finding, site: Site | None = None) -> float:
    if f.status is not Status.FOUND:
        return 0.0
    if f.confidence is not None and f.source != "sites-db":
        return f.confidence
    src = f.source
    if src in ("socialscan",):
        c = 0.95
    elif src in ("holehe", "user-scanner", "extras", "ignorant", "numint", "mailcat"):
        c = 0.85
    elif src == "search-engines":
        c = 0.5
    elif src == "sites-db":
        if site is None:
            c = 0.6
        else:
            d = site.detect
            types = d.get("type") if isinstance(d.get("type"), list) else [d.get("type")]
            has_found = bool(d.get("found_strings"))
            has_missing = bool(d.get("missing_strings"))
            if "profile_api" in types or "wmn" in types or (has_found and has_missing):
                c = 0.9
            elif has_missing or has_found:
                c = 0.75
            elif "response_url" in types:
                c = 0.65
            else:
                c = 0.55
            # Corroboration: every extra project that independently listed this site
            # is a little more evidence the rule is real.  Graduated rather than a
            # single >=3 step, so two agreeing sources already count for something.
            n = len(site.sources)
            if n >= 2:
                c += min(0.08, 0.02 * (n - 1))
            # A page that never mentions the name it was asked about has the shape
            # of a soft 404; without a positive marker that costs the rule further.
            mentions = (f.extra or {}).get("_page_mentions_query")
            if mentions is False and not has_found and "profile_api" not in types:
                c = min(c, 0.5)
            # Applied last on purpose: no amount of agreement about a site's URL
            # turns a status-code-only rule into proof that the account exists.
            if site.weak:
                c = min(c, 0.25 if mentions is False else 0.4)
    else:
        c = 0.6
    if f.extra:
        rich = len(enrichment_fields(f))
        c += min(0.1, 0.02 * rich)
    if site is not None and site.weak and src == "sites-db":
        f.extra["_confidence_cap"] = 0.25 if f.extra.get("_page_mentions_query") is False else 0.4
        c = min(c, f.extra["_confidence_cap"])
    return round(min(c, 0.99), 2)


def _norm_name(v: str) -> str:
    text = unicodedata.normalize("NFKC", str(v)).casefold()
    return "".join(ch for ch in text if ch.isalpha())


def _profile_name(f):
    # Only explicit top-level name attributes vote. Nested objects may describe
    # organizations, contacts or exposed devices instead of the queried person.
    fields = enrichment_fields(f)
    for key in NAME_KEYS:
        canonical = key.replace("_", "")
        values = {value for name, value in fields.items()
                  if name.lower().replace("_", "").replace(" ", "") == canonical
                  and isinstance(value, str) and value}
        if values:
            return next(iter(values)) if len(values) == 1 else None
    return None


def apply_consensus(findings: Iterable[Finding]) -> None:
    """Bump confidence of profiles whose display name matches the majority name
    across all found profiles of the same query, lower isolated outliers."""
    by_query: dict = {}
    seen = set()
    for f in findings:
        if id(f) in seen:
            continue
        seen.add(id(f))
        if f.status is Status.FOUND and f.category not in INFO_CATEGORIES:
            previous = getattr(f, "_consensus_scores", None)
            if previous is not None and f.confidence == previous[1]:
                f.confidence = previous[0]
            f.extra.pop("_consensus", None)
            f._consensus_scores = (f.confidence, f.confidence)
            by_query.setdefault((f.query, f.query_type), []).append(f)
    for _, group in by_query.items():
        from .modules import finding_service_key

        # Several adapters can report the same service. That is one source of
        # name evidence, and contradictory names from that source cast no vote.
        service_names: dict = {}
        for f in group:
            v = _profile_name(f)
            if v and 3 <= len(v) <= 60:
                name = _norm_name(v)
                if name:
                    service = finding_service_key(f, fallback=f.site_id)
                    if service is not None:
                        service_names.setdefault(service, set()).add(name)
        names = Counter(next(iter(values)) for values in service_names.values() if len(values) == 1)
        if not names:
            continue
        top, cnt = names.most_common(1)[0]
        if cnt < 2 or cnt * 2 <= sum(names.values()):
            continue
        for f in group:
            v = _profile_name(f)
            n = _norm_name(v) if v else None
            if not n or f.confidence is None:
                continue
            if n == top:
                cap = f.extra.get("_confidence_cap", 0.99)
                try:
                    valid_cap = type(cap) in (int, float) and math.isfinite(cap) and 0 <= cap <= 1
                except OverflowError:
                    valid_cap = False
                if not valid_cap:
                    cap = 0.99
                f.confidence = round(min(0.99, cap, f.confidence + 0.05), 2)
                f.extra.setdefault("_consensus", "name matches majority")
            elif cnt >= 3:
                f.confidence = round(max(0.05, f.confidence - 0.15), 2)
                f.extra.setdefault("_consensus", "name differs from majority")
            f._consensus_scores = (f._consensus_scores[0], f.confidence)
