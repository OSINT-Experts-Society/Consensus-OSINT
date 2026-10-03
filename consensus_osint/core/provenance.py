"""Recorded lookup coverage, never a claim that another tool works today.

Only explicit import lineage and recorded provider/app/identifier-type overlaps
are used. Saved results keep their scan-time snapshot; rendering never loads a
new catalogue or infers coverage from a returned profile URL.
"""
from __future__ import annotations

REPOSITORIES = {
    "sherlock": ("Sherlock", "sherlock-project/sherlock"),
    "maigret": ("Maigret", "soxoj/maigret"),
    "wmn": ("WhatsMyName", "WebBreacher/WhatsMyName"),
    "sherlockv2": ("SherlockV2", "hanyxd/sherlockV2"),
    "detectdee": ("DetectDee", "Yvesssn/DetectDee"),
    "aliens_eye": ("Aliens Eye", "arxhr007/Aliens_eye"),
    "nexfil": ("Nexfil", "thewhiteh4t/nexfil"),
    "gosearch": ("GoSearch", "ibnaleem/gosearch"),
    "vesper": ("Vesper", "krishpranav/vesper"),
    "findme": ("FindMe", "0xSaikat/findme"),
    "linkook": ("Linkook", "JackJuly/linkook"),
    "userjoo": ("UserJoo", "ar33s0/UserJoo"),
    "sreg": ("Sreg", "n0tr00t/Sreg"),
    "user-scanner": ("User Scanner", "kaifcodec/user-scanner"),
    "holehe": ("Holehe", "megadose/holehe"),
    "ignorant": ("Ignorant", "megadose/ignorant"),
    "socialscan": ("Socialscan", "iojw/socialscan"),
    "numint": ("Numint", "whoamitang/numint"),
    "mailcat": ("Mailcat", "sharsil/mailcat"),
    "consensus": ("Consensus (native)", "OSINT-Experts-Society/Consensus-OSINT"),
}
LEGEND = (
    "Tools with this lookup: [x] means the tool's imported catalogue lists this search, including disabled variants. "
    "It does not mean that tool ran separately, confirmed the result, or returns identical information. "
    "Missing historical tool names are stated explicitly."
)


def information_source(f) -> str:
    """Explain built-in analysis without attributing native code to an upstream tool."""
    if f.site_id == "email-local":
        return "Consensus · email syntax, DNS mail records and bundled provider/disposable-domain lists"
    if f.site_id == "phone-local":
        return "Consensus · phonenumbers / Google libphonenumber offline numbering data"
    if f.source == "phone" and f.category == "dorks":
        return "Consensus · bundled phone search templates, derived from PhoneInfoga and Telespotter; links only"
    if f.source == "phone":
        return f"Consensus · {f.site} lookup"
    if f.source == "search-engines":
        return "Consensus · public search-engine results"
    return ""


def _ids(values) -> set[str]:
    if not isinstance(values, (list, tuple, set)):
        return set()
    return {"consensus" if v in ("extras", "bundled") else v for v in values if isinstance(v, str)}


def direct_sources(f) -> set[str]:
    extra = f.extra if isinstance(f.extra, dict) else {}
    sources = _ids(extra.get("_sources"))
    if f.source == "rules":
        sources |= _ids([extra.get("_rule_source")])
        sources |= _ids([tag for tag in f.tags if tag in REPOSITORIES])
    elif f.source not in ("sites-db", "module"):
        sources |= _ids([f.source])
    if information_source(f):
        sources.add("consensus")
    return sources


def repository_coverage(f) -> list[dict]:
    """A safe, typed export projection from recorded metadata only."""
    direct = direct_sources(f)
    recorded = _ids(f.extra.get("_upstream_sources")) | direct
    out = []
    for source in sorted(recorded):
        if source in REPOSITORIES:
            name, repo = REPOSITORIES[source]
            out.append({"id": source, "name": name, "url": "https://github.com/" + repo,
                        "relationship": "origin" if source in direct else "same_host_and_identifier",
                        "recorded": True})
        elif source == "fediverse-observer":
            out.append({"id": source, "name": "Fediverse Observer (directory)",
                        "url": "https://fediverse.observer/", "relationship": "origin", "recorded": True})
    return out


def coverage_text(f) -> str:
    text = "\n".join("[x] " + r["name"] for r in repository_coverage(f))
    count = f.extra.get("_source_count")
    if not text and type(count) is int and count >= 2:
        return f"{count} imported lists; their names were not saved in this result"
    return text or f"Original tool names unavailable in this result (source: {f.source or 'not saved'})"


class CoverageIndex:
    """Conservative same-provider comparison across the local catalogue.

    Provider/app grouping follows scan-plan deduplication. No registrable-domain,
    display-name, email-local-part or returned-URL matching is performed.
    Disabled/restricted definitions remain listings, not supported variants.
    """

    @classmethod
    def installed(cls, sites=()):
        """Read available metadata without installation hints for unselected extras."""
        from importlib.util import find_spec

        from .modules import ADAPTERS, FAMILY_REQUIRES, all_modules

        families = [name for name in ADAPTERS
                    if name not in FAMILY_REQUIRES or find_spec(FAMILY_REQUIRES[name]) is not None]
        return cls(sites, all_modules(families=families))

    def __init__(self, sites=(), modules=()):
        from .modules import _service_host, _service_key, _site_service_key

        self.by_id = {}
        self.hosts = {}
        self.by_service = {}
        for item in sites:
            self._add(item.id, item.id_type, _service_host(item.domain or item.url_main or item.url),
                      _ids(item.sources), _site_service_key(item))
        for item in modules:
            sources = _ids(item.tags) & REPOSITORIES.keys() if item.source == "rules" else _ids([item.source])
            self._add(item.id, item.kind, _service_host(item.url_main), sources, _service_key(item.url_main))

    def _add(self, identifier, kind, host, sources, identity):
        key = (kind, identity) if identity else None
        self.by_id[(kind, identifier)] = (key, sources)
        self.hosts[(kind, identifier)] = host
        if key:
            self.by_service.setdefault(key, set()).update(sources)

    def annotate(self, f) -> None:
        key, origin = self.by_id.get((f.query_type, f.site_id), (None, set()))
        host = self.hosts.get((f.query_type, f.site_id))
        if host:
            f.extra["_service_host"] = host
        if key:
            f.extra["_service_identity"] = key[1]
        elif (f.query_type, f.site_id) in self.by_id:
            f.extra.pop("_service_identity", None)
        sources = direct_sources(f) | origin | self.by_service.get(key, set())
        # Retain original lineage even on skipped/error paths and after reloading.
        if origin:
            f.extra["_sources"] = sorted(direct_sources(f) | origin)
        if sources:
            f.extra["_upstream_sources"] = sorted(sources)
