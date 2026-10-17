"""Coverage-aware search continuation and comparisons of recorded observations."""
from __future__ import annotations

import copy
import json
import math
import time
from datetime import datetime, timezone

from .models import INFO_CATEGORIES, ScanSummary, Status
from .presentation import enrichment_fields


def identity(finding):
    key = finding.query, finding.query_type, finding.site_id, finding.source
    return key + (finding.url or "",) if finding.source == "search-engines" else key


def lookup_id(finding):
    return finding.extra.get("_lookup_id") or (
        ("site:" if finding.source == "sites-db" else "module:") + finding.site_id)


def inventory(sites=None):
    from .modules import all_modules
    from .phone import SERVICES
    from .sitesdb import SiteDB

    kinds = {}
    for site in sites if sites is not None else SiteDB.load().sites:
        if not site.effective_disabled:
            kinds.setdefault(site.id_type, set()).add("site:" + site.id)
    for module in all_modules():
        if not module.disabled_reason:
            kinds.setdefault(module.kind, set()).add("module:" + module.id)
    kinds.setdefault("phone", set()).update("phone:" + key for key in SERVICES)
    return {"schema": 1, "types": {kind: sorted(keys) for kind, keys in kinds.items()}}


def saved_inventory(summary):
    value = summary.options.get("lookup_inventory")
    if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("types"), dict):
        raise ValueError("This older search has no coverage snapshot. Run a new search to enable new-source searches.")
    for kind, keys in value["types"].items():
        if not isinstance(kind, str) or not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            raise ValueError("The saved coverage snapshot is damaged.")
    return value["types"]


def new_source_counts(summary, current=None):
    old = saved_inventory(summary)
    current = current or inventory()
    counts = {}
    for query in summary.queries:
        if query.get("parent"):
            continue
        kind = query["type"]
        completed = {lookup_id(f) for f in summary.findings
                     if f.query == query["query"] and f.query_type == kind and f.status.is_definitive}
        counts[kind] = counts.get(kind, 0) + len(set(current["types"].get(kind, [])) - set(old.get(kind, [])) - completed)
    return counts


class Continuation:
    def __init__(self, previous, mode):
        if mode not in ("continue", "new", "recheck", "retry"):
            raise ValueError("Unknown search action")
        self.previous, self.mode = previous, mode
        self.old = saved_inventory(previous) if mode == "new" else {}
        self.completed = {}
        self.retryable = {}
        self.deferred = 0
        cooling = set()
        now = time.time()
        for finding in previous.findings:
            if finding.status.is_definitive:
                self.completed.setdefault((finding.query, finding.query_type), set()).add(lookup_id(finding))
            if (mode == "retry" and finding.category not in INFO_CATEGORIES
                    and finding.status in (Status.ERROR, Status.BLOCKED, Status.UNKNOWN, Status.RATE_LIMITED)):
                if finding.status is Status.RATE_LIMITED:
                    # Never immediately hammer a throttled service. Honour a recorded
                    # numeric Retry-After when available; otherwise wait at least a minute.
                    delay = finding.extra.get("retry_after", 60)
                    try:
                        valid_delay = type(delay) in (int, float) and math.isfinite(delay) and delay >= 60
                    except OverflowError:
                        valid_delay = False
                    if not valid_delay:
                        delay = 60
                    if now < finding.ts + delay:
                        cooling.add((finding.query, finding.query_type, lookup_id(finding)))
                        continue
                self.retryable.setdefault((finding.query, finding.query_type), set()).add(lookup_id(finding))
        # One throttled observation suppresses the entire lookup, even if another
        # result from it was an error. Input order must not bypass a cooldown.
        for query, kind, key in cooling:
            self.retryable.get((query, kind), set()).discard(key)
        self.deferred = len(cooling)

    def allows(self, query, kind, key):
        if self.mode == "retry":
            return (key in self.retryable.get((query, kind), set())
                    and key not in self.completed.get((query, kind), set()))
        if self.mode == "new":
            return key not in self.old.get(kind, []) and key not in self.completed.get((query, kind), set())
        return self.mode == "recheck" or key not in self.completed.get((query, kind), set())

    def select(self, query, kind, items, prefix):
        return [item for item in items if self.allows(query, kind, prefix + item.id)]

    def exclude_completed_alternatives(self, query, kind, sites, modules, pairs):
        if self.mode == "recheck":
            return sites, modules
        completed = {key.partition(":")[2] for key in self.completed.get((query, kind), set())}
        excluded = {kept for kept, alternative in pairs if alternative in completed}
        return ([s for s in sites if s.id not in excluded], [m for m in modules if m.id not in excluded])

    def merge(self, fresh):
        # Replace observations that were actually made; never let the old
        # positive-winning deduplicator hide a later negative or failed check.
        changes = compare(self.previous, fresh)
        reviews = {identity(f): f.extra["_analyst_review"] for f in self.previous.findings
                   if "_analyst_review" in f.extra}
        for finding in fresh.findings:
            if identity(finding) in reviews:
                finding.extra["_analyst_review"] = copy.deepcopy(reviews[identity(finding)])
        replaced = {(f.query, f.query_type, lookup_id(f)) for f in fresh.findings}
        kept = [f for f in self.previous.findings if (f.query, f.query_type, lookup_id(f)) not in replaced]
        fresh.findings = kept + fresh.findings
        known = {(q["query"], q["type"]) for q in fresh.queries}
        fresh.queries += [copy.deepcopy(q) for q in self.previous.queries if (q["query"], q["type"]) not in known]
        fresh.options["continuation"] = {"mode": self.mode, "previous_started": self.previous.started,
                                         "retained_results": len(kept)}
        fresh.options["changes"] = changes
        if "investigation" in self.previous.options:
            fresh.options["investigation"] = copy.deepcopy(self.previous.options["investigation"])
        # A stopped new-source search must retain the old inventory so its
        # remaining additions are still offered when the user tries again.
        if self.mode == "new":
            fresh.options["lookup_inventory"] = copy.deepcopy(self.previous.options["lookup_inventory"])
        return fresh


def compare(previous, current):
    before = {identity(f): f for f in previous.findings if f.category not in INFO_CATEGORIES}
    # Repeated failed attempts must not erase the last definite observation or
    # make a recovered, already-known match appear newly discovered.
    from .models import Finding
    for row in previous.options.get("changes", {}).get("rows", []):
        evidence = row.get("previous_evidence")
        if evidence:
            known = Finding.from_dict(evidence)
            key = identity(known)
            if known.status.is_definitive and key in before and not before[key].status.is_definitive:
                before[key] = known
    after = {identity(f): f for f in current.findings if f.category not in INFO_CATEGORIES}
    rows = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        f = new or old
        fields = []
        if new is None or (old is not None and old.ts == new.ts and old.to_dict() == new.to_dict()):
            change = "Not rechecked"
        elif new.status in (Status.ERROR, Status.BLOCKED, Status.RATE_LIMITED, Status.UNKNOWN, Status.SKIPPED):
            change = "Inconclusive"
        elif new.found and (old is None or not old.found):
            change = "Newly discovered"
        elif old is not None and old.found and new.status is Status.NOT_FOUND:
            change = "No longer observed"
        elif old is not None and old.found and new.found:
            a, b = enrichment_fields(old), enrichment_fields(new)
            fields = [k for k in sorted(a.keys() | b.keys()) if a.get(k) != b.get(k)]
            if old.url != new.url:
                fields.append("profile URL")
            change = "Details changed" if fields else "Unchanged"
        else:
            change = "Unchanged"
        rows.append({"query": f.query, "query_type": f.query_type, "site": f.site, "site_id": f.site_id,
                     "source": f.source, "change": change, "fields": fields,
                     "before": old.status.value if old else None, "after": new.status.value if new else None,
                     "previous_observed": old.ts if old else None, "observed": new.ts if new else None,
                     "previous_evidence": old.to_dict() if old and change in ("Inconclusive", "No longer observed", "Details changed") else None})
    return {"previous_started": previous.started, "current_started": current.started, "rows": rows,
            "note": "Newly discovered does not mean newly created. No longer observed does not prove deletion. "
                    "Blocked, failed and unsearched sources remain inconclusive."}


def observation_time(finding):
    try:
        return datetime.fromtimestamp(finding.ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError, OSError, TypeError):
        return "Not recorded"


def load_summary(value):
    from .models import Finding
    if not isinstance(value, dict) or not isinstance(value.get("findings"), list):
        raise ValueError("Invalid saved results")
    queries, options = value.get("queries", []), value.get("options", {})
    if not isinstance(queries, list) or not isinstance(options, dict):
        raise ValueError("Invalid saved search metadata")
    if any(not isinstance(q, dict) or not isinstance(q.get("query"), str) or not isinstance(q.get("type"), str)
           for q in queries):
        raise ValueError("Invalid saved search identifiers")
    if "changes" in options:
        changes = options["changes"]
        if not isinstance(changes, dict) or not isinstance(changes.get("rows"), list) or not isinstance(changes.get("note"), str):
            raise ValueError("Invalid saved comparison")
        for row in changes["rows"]:
            if (not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in
                    ("query", "query_type", "site", "site_id", "source", "change"))
                    or not isinstance(row.get("fields"), list) or not all(isinstance(k, str) for k in row["fields"])):
                raise ValueError("Invalid saved comparison row")
            if row.get("previous_evidence") is not None:
                Finding.from_dict(row["previous_evidence"])
    # Validate scalar metadata as well as findings, including extreme timestamps.
    import math
    for key in ("started", "finished"):
        number = value.get(key, 0 if key == "started" else None)
        try:
            valid = (number is None and key == "finished") or (type(number) in (float, int) and math.isfinite(number))
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("Invalid saved search time")
    return ScanSummary(queries=queries, options=options, started=value.get("started", 0), finished=value.get("finished"),
                       findings=[Finding.from_dict(f) for f in value["findings"]])


def clone_summary(summary):
    return load_summary(json.loads(json.dumps(summary.to_dict())))
