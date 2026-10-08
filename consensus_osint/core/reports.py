"""Report / export layer.

Every format consumes a :class:`~consensus_osint.core.models.ScanSummary` and
never touches the network.  Formats::

    txt    grouped plain text (query -> category -> one line per finding)
    md     Markdown with a table per query and bullet-list metadata
    html   self-contained single page (Jinja2 template ``report.html.j2``)
    csv    flat table, one row per finding (formula-injection safe)
    json   ``ScanSummary.to_dict()`` pretty-printed
    jsonl  one finding per line (ndjson)
    neo4j  JSON graph: query nodes, site nodes, FOUND_ON / DISCOVERED edges
    pdf    reportlab document (optional dependency ``consensus-osint[pdf]``)
    xmind  mind map (XMind 8 ``content.xml`` + XMind Zen ``content.json``)

``include_all=False`` (the default) writes only FOUND findings plus the
overall status counts; ``include_all=True`` writes every finding.

Nothing here swallows exceptions on purpose: a broken report raises and the
CLI decides what to do about it.  The renderers are, however, defensive about
odd data (missing URLs, nested ``extra`` values, non-string keys ...).

Ideas (not code) borrowed from the report modules of Maigret, user-scanner
and linkook, all MIT licensed.
"""
from __future__ import annotations

import csv
import html as _html
import io
import json
import math
import os
import re
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from .. import __version__
from .branding import DESCRIPTION, HEALTH_WARNING, LINKS, MENU, ORGANIZATION, SLOGAN, UPDATE_NOTE, report_identity
from .common_details import comparisons
from .continuity import observation_time
from .models import INFO_CATEGORIES, Finding, QueryType, ScanSummary, Status, redact_options
from .presentation import assessment, enrichment_fields, has_details, split_fields
from .provenance import LEGEND, coverage_text, information_source, repository_coverage

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
HTML_TEMPLATE = "report.html.j2"
GENERATOR = f"consensus-osint {__version__}"

FORMATS = ("txt", "md", "html", "csv", "json", "jsonl", "neo4j", "pdf", "xmind", "graph-html")

_FORMAT_ALIASES = {
    "text": "txt",
    "plain": "txt",
    "markdown": "md",
    "htm": "html",
    "ndjson": "jsonl",
    "graph": "neo4j",
    "cypher": "neo4j",
}

_EXT_TO_FORMAT = {
    ".txt": "txt",
    ".text": "txt",
    ".md": "md",
    ".markdown": "md",
    ".html": "html",
    ".htm": "html",
    ".csv": "csv",
    ".json": "json",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".pdf": "pdf",
    ".xmind": "xmind",
}

# Display order of statuses (also the order used inside "other results").
_STATUS_ORDER = [
    Status.FOUND,
    Status.NOT_FOUND,
    Status.UNKNOWN,
    Status.BLOCKED,
    Status.RATE_LIMITED,
    Status.ERROR,
    Status.SKIPPED,
]

_COUNT_LABELS = {
    Status.FOUND: "found",
    Status.NOT_FOUND: "not found",
    Status.UNKNOWN: "unknown",
    Status.BLOCKED: "blocked",
    Status.RATE_LIMITED: "rate limited",
    Status.ERROR: "errors",
    Status.SKIPPED: "skipped",
}

# extra{} keys that hold a profile picture (rendered as avatar, hidden from field lists)
_IMAGE_KEYS = (
    "image",
    "avatar",
    "thumbnailurl",
    "thumbnail_url",
    "avatar_url",
    "image_url",
    "profile_image",
    "profile_image_url",
    "profile_picture",
    "picture",
    "photo",
    "pfp",
)

# Most useful metadata first (txt uses the first few, html/md use all of them).
_FIELD_PRIORITY = [
    "fullname", "name", "full_name", "display_name", "nickname", "username", "login",
    "id", "uid", "user_id",
    "bio", "description", "about",
    "location", "country", "city", "region", "locale", "language",
    "gender", "age", "birthday", "born",
    "created_at", "joined", "registered", "last_seen", "last_online", "updated_at",
    "follower_count", "followers", "followers_count", "following_count", "following",
    "friends_count", "posts_count", "tweets_count", "karma", "reputation",
    "email", "emails", "phone", "phones",
    "website", "websites", "links", "urls", "social_links",
    "verified", "is_verified", "is_private", "is_business",
]
_FIELD_RANK = {k: i for i, k in enumerate(_FIELD_PRIORITY)}

_WS_RE = re.compile(r"\s+")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff\ufffe\uffff]")


# --------------------------------------------------------------------------- helpers
def _status(f: Finding) -> Status:
    """Coerce ``f.status`` to :class:`Status` (tolerates raw strings)."""
    s = f.status
    if isinstance(s, Status):
        return s
    try:
        return Status(str(s))
    except ValueError:
        return Status.UNKNOWN


def _n(value: int) -> str:
    """Thousands-separated integer."""
    return f"{int(value):,}"


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return ""
    try:
        # A report is handed to other people: state the offset so the local
        # time cannot be mistaken for UTC or for the reader's own zone.
        local = datetime.fromtimestamp(float(ts)).astimezone()
        offset = local.strftime("%z")
        return local.strftime("%Y-%m-%d %H:%M:%S") + (f" UTC{offset[:3]}:{offset[3:5]}" if offset else "")
    except (OverflowError, OSError, ValueError, TypeError):
        return str(ts)


def _fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return ""
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return ""
    if not math.isfinite(s):
        return ""
    if s < 0:
        s = 0.0
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(int(round(s)), 60)
    if m < 60:
        return f"{m}m {sec:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m {sec:02d}s"


def _duration(summary: ScanSummary) -> float | None:
    if not summary.started:                 # absent from the input: unknown, not "since 1970"
        return None
    end = summary.finished if summary.finished else time.time()
    try:
        return max(0.0, float(end) - float(summary.started))
    except (TypeError, ValueError):
        return None


def _clean_text(value: str, limit: int = 0) -> str:
    """Collapse whitespace / control chars and optionally truncate."""
    s = _CTRL_RE.sub("", str(value))
    s = _WS_RE.sub(" ", s).strip()
    if limit and len(s) > limit:
        s = s[: max(1, limit - 1)].rstrip() + "…"
    return s


def _is_scalar(v: Any) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))


def _compact_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _compact(value: Any, limit: int = 0) -> str:
    """Human-friendly single-line rendering of any ``extra`` value."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _clean_text(value, limit)
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if all(_is_scalar(i) for i in items):
            return _clean_text(", ".join(_compact(i) for i in items if i is not None and i != ""), limit)
        return _clean_text(_compact_json(items), limit)
    if isinstance(value, dict):
        return _clean_text(_compact_json(value), limit)
    return _clean_text(str(value), limit)


def _safe_http_url(value: Any) -> str | None:
    """Return ``value`` when it is a plain http(s) URL, else ``None``.

    Used for every ``href``/``src`` we emit: scraped metadata is attacker
    influenced, so ``javascript:``, ``data:`` and friends are never linked.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or len(s) > 2048 or _WS_RE.search(s) or _CTRL_RE.search(s):
        return None
    try:
        parts = urlsplit(s)
        if not parts.hostname or parts.username is not None or parts.password is not None:
            return None
        _ = parts.port  # validate an explicitly supplied port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return None
    return s


def _is_image_key(key: Any) -> bool:
    k = str(key).lower().rsplit(".", 1)[-1]
    return k in _IMAGE_KEYS or k.endswith("_image") or k.endswith("_avatar") or k.endswith("_photo")


def result_link(f: Finding) -> tuple[str | None, str]:
    """A navigable result, without inventing or verifying a public profile URL."""
    if f.status is Status.FOUND and f.category not in INFO_CATEGORIES:
        fields, _ = split_fields(f.extra)
        for key, value in fields.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if normalized in ("profileurl", "profilelink", "othersprofileurl"):
                if url := _safe_http_url(value):
                    if f.extra.get("_profile_url_source") == "constructed":
                        return url, "Constructed profile link; verify the page and query"
                    if f.extra.get("_profile_url_source") == "resolved from labelled profile link":
                        return url, "Link from the profile field; verify the page and query"
                    return url, "Profile link supplied by this check; verify the page and query"
    url = _safe_http_url(f.url)
    if not url:
        return None, "No public profile link returned"
    if f.category == "dorks":
        return url, "Suggested search; not run"
    if urlsplit(url).path in ("", "/"):
        return url, "Service website; no profile link returned"
    if f.status is not Status.FOUND:
        return url, "Page checked; no profile confirmed"
    return url, "Result page; verify it matches the query"


def _field_label(key: Any) -> str:
    k = str(key).replace("_", " ").replace("-", " ").strip()
    return k[:1].upper() + k[1:] if k else "?"


def _field_sort_key(item: tuple) -> tuple:
    key = str(item[0]).lower()
    return (_FIELD_RANK.get(key, len(_FIELD_RANK)), key)


def _extra_dict(extra: Any) -> dict:
    if isinstance(extra, dict):
        return extra
    if extra is None or extra == "" or extra == [] or extra == ():
        return {}
    return {"data": extra}


def _avatar_url(extra: Any) -> str | None:
    """First safe http(s) picture URL from an ``extra`` dict."""
    extra, _ = split_fields(extra)
    lowered = {str(k).lower(): v for k, v in extra.items()}
    for key in _IMAGE_KEYS:
        url = _safe_http_url(lowered.get(key))
        if url:
            return url
    for k, v in extra.items():
        if _is_image_key(k):
            url = _safe_http_url(v)
            if url:
                return url
    return None


@dataclass
class DisplayField:
    """One metadata line prepared for rendering."""

    key: str
    label: str
    value: str                                  # single-line, truncated text
    urls: list = field(default_factory=list)    # safe http(s) URLs when the value is a link / list of links


def display_fields(extra: Any, *, limit: int = 500, max_fields: int = 0, include_images: bool = False) -> list:
    """Turn ``Finding.extra`` into an ordered list of :class:`DisplayField`.

    Picture keys are dropped unless ``include_images`` is set, empty
    values are skipped, nested values become compact JSON and URL values are
    exposed through ``urls`` so templates can make them clickable.
    """
    items = []
    for k, v in _extra_dict(extra).items():
        if _is_image_key(k) and not include_images:
            continue
        if v is None or v == "" or v == [] or v == {}:
            continue
        items.append((k, v))
    items.sort(key=_field_sort_key)
    out: list = []
    for k, v in items:
        urls: list = []
        if isinstance(v, str):
            u = _safe_http_url(v)
            if u:
                urls = [u]
        elif isinstance(v, (list, tuple, set, frozenset)):
            cand = [_safe_http_url(i) for i in v]
            if cand and all(cand):
                urls = [u for u in cand if u]
        out.append(DisplayField(key=str(k), label=_field_label(k), value=_compact(v, limit), urls=urls))
        if max_fields and len(out) >= max_fields:
            break
    return out


def _kv_line(extra: Any, max_fields: int = 0, limit: int = 0) -> str:
    """Compact ``key=value key2="value two"`` string for text output."""
    parts = []
    for df in display_fields(extra, limit=limit, max_fields=max_fields, include_images=True):
        v = df.value
        if not v:
            continue
        if any(ch in v for ch in " =\"'"):
            v = '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        parts.append(f"{df.key}={v}")
    return " ".join(parts)


def _confidence_text(f: Finding) -> str:
    """Human assessment; numerical heuristics remain in structured exports."""
    return assessment(f)[0]


# --------------------------------------------------------------------------- grouping
@dataclass
class QueryView:
    """All findings that belong to one query, split for rendering."""

    query: str
    query_type: str
    parent: str | None = None
    depth: int = 0
    findings: list = field(default_factory=list)

    @property
    def title(self) -> str:
        return f"{self.query} ({self.query_type})"

    @property
    def found(self) -> list:
        return [f for f in self.findings if _status(f) is Status.FOUND]

    @property
    def others(self) -> list:
        order = {s: i for i, s in enumerate(_STATUS_ORDER)}
        rest = [f for f in self.findings if _status(f) is not Status.FOUND]
        rest.sort(key=lambda f: (order.get(_status(f), 99), str(f.category).lower(), str(f.site).lower()))
        return rest

    def counts(self) -> dict:
        c: dict = {}
        for f in self.findings:
            s = _status(f).value
            c[s] = c.get(s, 0) + 1
        return c

    def by_category(self, findings: list | None = None) -> list:
        """``[(category, [findings sorted by status then site]), ...]`` with ``misc`` last."""
        src = self.found if findings is None else findings
        groups: dict = {}
        for f in src:
            groups.setdefault(str(f.category or "misc"), []).append(f)
        cats = sorted(groups, key=lambda c: (c.lower() == "misc", c.lower()))
        order = {s: i for i, s in enumerate(_STATUS_ORDER)}
        return [
            (c, sorted(groups[c], key=lambda f: (order.get(_status(f), 99), str(f.site).lower())))
            for c in cats
        ]


def group_by_query(summary: ScanSummary) -> list:
    """Order queries as requested, then recursion-discovered ones by first appearance."""
    views: dict = {}
    order: list = []
    inferred: dict = {}
    for finding in summary.findings or []:
        inferred.setdefault(str(finding.query), finding.query_type)

    def get(q: str, qtype: str | None = None) -> QueryView:
        q = str(q)
        qtype = qtype or inferred.get(q) or QueryType.detect(q).value
        qtype = qtype.value if isinstance(qtype, QueryType) else str(qtype)
        key = (q, qtype)
        if key not in views:
            views[key] = QueryView(query=q, query_type=qtype)
            order.append(key)
        return views[key]

    for q in summary.queries or []:
        if isinstance(q, (list, tuple)) and q:
            get(str(q[0]), q[1] if len(q) > 1 else None)
        elif isinstance(q, dict) and q.get("query"):
            get(str(q["query"]), q.get("query_type") or q.get("type"))
        elif q is not None:
            get(str(q))
    for f in summary.findings or []:
        v = get(str(f.query), f.query_type)
        v.findings.append(f)
        if f.parent and not v.parent:
            v.parent = str(f.parent)
            v.depth = int(f.depth or 0)
    return [views[k] for k in order]


def summary_counts_line(summary: ScanSummary) -> str:
    """``found 42 · not found 3,100 · blocked 30 · errors 8`` (zero counts omitted, found always shown)."""
    counts: dict = {}
    for f in summary.findings or []:
        s = _status(f).value
        counts[s] = counts.get(s, 0) + 1
    parts = []
    for st in _STATUS_ORDER:
        n = int(counts.get(st.value, 0) or 0)
        if n or st is Status.FOUND:
            parts.append(f"{_COUNT_LABELS[st]} {_n(n)}")
    return " · ".join(parts)


def _facts(summary: ScanSummary, views: list) -> dict:
    """Header facts shared by every renderer."""
    findings = summary.findings or []
    top = [v for v in views if not v.parent] or views
    return {
        "generator": GENERATOR,
        "generated": _fmt_ts(time.time()),
        "queries": ", ".join(v.title for v in top),
        "started": _fmt_ts(summary.started),
        "finished": _fmt_ts(summary.finished),
        "duration": _fmt_duration(_duration(summary)),
        "checks": _n(len(findings)),
        "found": _n(sum(1 for f in findings if _status(f) is Status.FOUND)),
        "matches": _n(sum(1 for f in findings if _status(f) is Status.FOUND and f.category not in INFO_CATEGORIES)),
        "details": _n(sum(has_details(f) for f in findings)),
        "review": _n(sum(assessment(f)[0] == "Needs review" for f in findings)),
        "inconclusive": _n(sum(f.category not in INFO_CATEGORIES and
                               _status(f) in (Status.UNKNOWN, Status.ERROR, Status.BLOCKED, Status.RATE_LIMITED)
                               for f in findings)),
        "interrupted": bool((summary.options or {}).get("interrupted")),
        "omitted": (summary.options or {}).get("_input_omitted_results", 0),
        "counts_line": summary_counts_line(summary),
    }


# --------------------------------------------------------------------------- text
def _quote(value: str) -> str:
    if any(ch in value for ch in " =\"'"):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def _text_line(f: Finding) -> str:
    st = _status(f)
    label, explanation, _ = assessment(f)
    site = _clean_text(str(f.site or f.site_id or "?"), 40)
    line = f"  {label:<12} {site:<24} {_clean_text(str(f.url)) if f.url else '-'}"
    notes = []
    if f.error:
        notes.append(f"error={_quote(_clean_text(str(f.error)))}")
    if f.http_status and st is not Status.FOUND:
        notes.append(f"http={f.http_status}")
    if f.loud:
        notes.append("loud")
    if f.nsfw:
        notes.append("nsfw")
    if notes:
        line += "  " + " ".join(notes)
    line += "\n    Meaning: " + explanation
    line += "\n    Observed: " + observation_time(f)
    kv = _kv_line(split_fields(f.extra)[0])
    if kv:
        line += "\n    " + _field_heading(f) + ": " + kv
    line += "\n    Tools with this lookup: " + coverage_text(f).replace("\n", "; ")
    return line.rstrip()


def _field_heading(f: Finding) -> str:
    if f.category in INFO_CATEGORIES:
        return "Supporting information"
    return "Returned details" if _status(f) is Status.FOUND else "Unconfirmed returned fields"


def render_text(summary: ScanSummary, include_all: bool = False) -> str:
    """Plain text with each finding's scope, returned fields and source coverage."""
    views = group_by_query(summary)
    facts = _facts(summary, views)
    out = ["[ OES ] Consensus report", SLOGAN, DESCRIPTION, UPDATE_NOTE, f"By {ORGANIZATION}",
           " | ".join(url for _, url in LINKS), HEALTH_WARNING, LEGEND,
           f"Generated: {facts['generated']} ({facts['generator']})"]
    if facts["queries"]:
        out.append(f"Queries:   {facts['queries']}")
    run = []
    if facts["started"]:
        run.append(f"started {facts['started']}")
    if facts["duration"]:
        run.append(f"duration {facts['duration']}")
    run.append(f"checks {facts['checks']}")
    out.append("Run:       " + " · ".join(run))
    for v in views:
        out.append("")
        head = f"== {_clean_text(v.title)}"
        if v.parent:
            head += f" — discovered via {_clean_text(v.parent)} (depth {v.depth})"
        out.append(f"{head} ==  positive signals {_n(len(v.found))} of {_n(len(v.findings))}")
        rows = v.findings if include_all else v.found
        if not include_all and _unlisted_line(v):
            out.append("  " + _unlisted_line(v))
        if not rows:
            out.append("  (no positive lookup signals)")
            continue
        for cat, items in v.by_category(rows):
            out.append(f"[{_clean_text(cat)}]")
            out.extend(_text_line(f) + "\n" + "─" * 72 for f in items)
    out.append("")
    out.append(f"Recorded outcomes: {facts['counts_line']}")
    out.extend(["", "Commands to run next:"] + [f"{label}: {command}" for label, command in MENU])
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- markdown
def _md_text(value: Any, limit: int = 0, cell: bool = False) -> str:
    """Escape user data for Markdown (inline HTML neutralised, pipes escaped in cells)."""
    s = _html.escape(_clean_text(str(value), limit), quote=False)
    s = s.replace("\\", "\\\\")
    for char in "`*_[]":
        s = s.replace(char, "\\" + char)
    if cell:
        s = s.replace("|", "\\|")
    return s


def _md_link(url: Any) -> str:
    """Clickable autolink for safe http(s) URLs, code span otherwise."""
    if url is None or url == "":
        return ""
    u = _safe_http_url(url)
    if u and "<" not in u and ">" not in u:
        return f"<{u}>"
    return "`" + _clean_text(str(url), 200).replace("`", "") + "`"


def _md_field(df: DisplayField) -> str:
    if df.urls:
        val = ", ".join(_md_link(u) for u in df.urls)
    else:
        val = _md_text(df.value)
    return f"  - **{_md_text(df.label)}:** {val}"


def _unlisted_line(view) -> str:
    """What a matches-only report leaves out for one query, so silence is not read as a negative."""
    rest = [f for f in view.findings if f.status is not Status.FOUND and f.category not in INFO_CATEGORIES]
    if not rest:
        return ""
    no_match = sum(f.status is Status.NOT_FOUND for f in rest)
    skipped = sum(f.status is Status.SKIPPED for f in rest)
    return (f"Not listed (saved without -a): no match {_n(no_match)}, inconclusive {_n(len(rest) - no_match - skipped)}, "
            f"skipped {_n(skipped)}. An inconclusive or skipped check is not a negative result.")


def render_markdown(summary: ScanSummary, include_all: bool = False) -> str:
    """Markdown: scoped results per query and clearly labelled returned fields."""
    views = group_by_query(summary)
    facts = _facts(summary, views)
    out = ["# Consensus report", "", f"**{SLOGAN}**", "", DESCRIPTION, "", UPDATE_NOTE, ""]
    out.extend([f"**By {ORGANIZATION}**", "", " · ".join(_md_link(url) for _, url in LINKS),
                "", HEALTH_WARNING, "", LEGEND, ""])
    out.append(f"- **Generated:** {facts['generated']} ({facts['generator']})")
    if facts["queries"]:
        out.append(f"- **Queries:** {_md_text(facts['queries'])}")
    run = []
    if facts["started"]:
        run.append(f"started {facts['started']}")
    if facts["duration"]:
        run.append(f"duration {facts['duration']}")
    run.append(f"checks {facts['checks']}")
    out.append("- **Run:** " + " · ".join(run))
    out.append(f"- **Recorded outcomes:** {facts['counts_line']}")
    for v in views:
        out.append("")
        out.append(f"## {_md_text(v.title)}")
        out.append("")
        if v.parent:
            out.append(f"_Discovered via {_md_text(v.parent)} (depth {v.depth})._")
            out.append("")
        rows = v.findings if include_all else v.found
        out.append(f"Positive signals: {_n(len(v.found))} of {_n(len(v.findings))} checks; see each result's scope below.")
        out.append("")
        if not include_all and _unlisted_line(v):
            out.extend([_md_text(_unlisted_line(v)), ""])
        if not rows:
            continue
        out.append("| Site | Category | Result | URL | Result scope | Note | Tools with this lookup |")
        out.append("|---|---|---|---|---|---|---|")
        for cat, items in v.by_category(rows):
            for f in items:
                st = _status(f)
                label, explanation, _ = assessment(f)
                note = "Observed: " + observation_time(f)
                if f.error:
                    note += "; " + _md_text(f.error, cell=True)
                elif f.http_status and st is not Status.FOUND:
                    note += f"; HTTP {f.http_status}"
                url = _md_link(f.url).replace("|", "%7C")
                out.append(
                    f"| {_md_text(f.site or f.site_id, 60, cell=True)} | {_md_text(cat, 40, cell=True)} "
                    f"| {_md_text(label, cell=True)} | {url} | {_md_text(explanation, cell=True)} | {note} | "
                    f"{_md_text(coverage_text(f).replace(chr(10), '; '), cell=True)} |"
                )
        detailed = [f for f in rows if display_fields(split_fields(f.extra)[0], max_fields=1, include_images=True)]
        if detailed:
            out.append("")
            out.append("**Returned details**")
            out.append("")
            for f in detailed:
                out.append(f"- **{_md_text(f.site or f.site_id, 60)}** — {_md_link(f.url)} — {_field_heading(f)}")
                for df in display_fields(split_fields(f.extra)[0], limit=0, include_images=True):
                    out.append(_md_field(df))
    out.append("")
    out.append(f"_Generated by {facts['generator']}. Verify every finding before drawing conclusions: "
               "identical usernames are frequently used by different people._")
    out.extend(["", "**Commands to run next**", ""] + [f"- {label}: `{command}`" for label, command in MENU])
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- csv
CSV_COLUMNS = [
    "query", "query_type", "site", "site_id", "category", "status", "url",
    "source", "method", "confidence", "extra_json", "error", "upstream_repositories",
    "assessment", "explanation", "observed_at",
]


def _csv_cell(value: Any) -> str:
    """Stringify and neutralise spreadsheet formula injection (OWASP)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    s = str(value)
    if s and (s[0] in "=+-@\t\r\n" or s.lstrip().startswith(("=", "+", "-", "@"))):
        s = "'" + s
    return s


def render_csv(summary: ScanSummary, include_all: bool = False) -> str:
    """Flat CSV, one row per finding.  Nested ``extra`` is kept as compact JSON."""
    rows = summary.findings or []
    if not include_all:
        rows = [f for f in rows if _status(f) is Status.FOUND]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for f in rows:
        extra = _extra_dict(f.extra)
        w.writerow([
            _csv_cell(f.query),
            _csv_cell(f.query_type),
            _csv_cell(f.site),
            _csv_cell(f.site_id),
            _csv_cell(f.category),
            _csv_cell(_status(f).value),
            _csv_cell(f.url),
            _csv_cell(f.source),
            _csv_cell(f.method),
            _csv_cell("" if f.confidence is None else f.confidence),
            _csv_cell(_compact_json(extra) if extra else ""),
            _csv_cell(f.error),
            _csv_cell(_compact_json(repository_coverage(f))),
            _csv_cell(assessment(f)[0]),
            _csv_cell(assessment(f)[1]),
            _csv_cell(observation_time(f)),
        ])
    return buf.getvalue()


# --------------------------------------------------------------------------- json / jsonl
def _finding_dict(f: Finding) -> dict:
    d = dict(f.to_dict()) if isinstance(f.status, Status) else dict(vars(f))
    d["status"] = _status(f).value
    return d


def _counts(findings: list) -> dict:
    c: dict = {}
    for f in findings:
        s = _status(f).value
        c[s] = c.get(s, 0) + 1
    return c


def _json_dumps(obj: Any, indent: int | None = 2) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=indent, default=str)


def build_json(summary: ScanSummary, include_all: bool = False) -> dict:
    """``ScanSummary.to_dict()`` plus generator info; findings filtered unless ``include_all``."""
    findings = summary.findings or []
    rows = findings if include_all else [f for f in findings if _status(f) is Status.FOUND]
    return {
        "generator": GENERATOR,
        "generated": time.time(),
        "include_all": bool(include_all),
        "queries": list(summary.queries or []),
        "started": summary.started,
        "finished": summary.finished,
        "options": redact_options(summary.options),
        "counts": _counts(findings),
        "findings": [_finding_dict(f) for f in rows],
        "comparisons": comparisons(summary),
    }


def render_json(summary: ScanSummary, include_all: bool = False) -> str:
    return _json_dumps(build_json(summary, include_all)) + "\n"


def render_jsonl(summary: ScanSummary, include_all: bool = False) -> str:
    """One finding per line (ndjson)."""
    rows = summary.findings or []
    if not include_all:
        rows = [f for f in rows if _status(f) is Status.FOUND]
    return "".join(_json_dumps(_finding_dict(f), indent=None) + "\n" for f in rows)


def save_json(summary: ScanSummary, path: str | Path, include_all: bool = False) -> Path:
    """Write :func:`build_json` as pretty JSON and return the path."""
    p = Path(path)
    _write_report(p, render_json(summary, include_all))
    return p


# --------------------------------------------------------------------------- neo4j
NEO4J_CYPHER_IMPORT = (
    "CALL apoc.load.json('file:///report.neo4j.json') YIELD value\n"
    "CALL { WITH value UNWIND value.nodes AS n\n"
    "       CALL apoc.merge.node(n.labels, {id: n.id}, n.properties, {}) YIELD node RETURN count(node) AS nodes }\n"
    "CALL { WITH value UNWIND value.edges AS e\n"
    "       MATCH (a {id: e.source}), (b {id: e.target})\n"
    "       CALL apoc.merge.relationship(a, e.type, {url: coalesce(e.properties.url, '')}, {}, b, {}) YIELD rel\n"
    "       SET rel = e.properties SET rel.url = coalesce(e.properties.url, '')\n"
    "       RETURN count(rel) AS rels }\n"
    "RETURN nodes, rels"
)


def _neo4j_label(query_type: str) -> str:
    parts = [p for p in re.split(r"[^0-9A-Za-z]+", str(query_type or "")) if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) or "Other"


def _neo4j_value(value: Any) -> Any:
    """Neo4j properties must be primitives or homogeneous arrays of primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [i for i in value if i is not None]
        if items and all(isinstance(i, str) for i in items):
            return items
        if items and all(isinstance(i, bool) for i in items):
            return items
        if items and all(isinstance(i, (int, float)) and not isinstance(i, bool) for i in items):
            return items
        return [_compact(i) if not isinstance(i, str) else i for i in items]
    return _compact_json(value)


def build_neo4j(summary: ScanSummary, include_all: bool = False) -> dict:
    """Graph JSON: ``Query`` and ``Site`` nodes, ``FOUND_ON`` edges (``CHECKED_ON``
    for non-found statuses when ``include_all``) and ``DISCOVERED`` edges from a
    query to the queries recursion derived from it (``Finding.parent``)."""
    views = group_by_query(summary)
    qtypes: dict = {}
    for v in views:
        qtypes.setdefault(v.query, set()).add(v.query_type)
    nodes: list = []
    edges: list = []
    seen: set = set()

    def query_node(q: str, depth: int = 0, qtype: str | None = None) -> str:
        q = str(q)
        key = q
        types = qtypes.get(key, set())
        qt = qtype or (next(iter(types)) if len(types) == 1 else QueryType.detect(q).value)
        # Preserve existing ids for ordinary reports; disambiguate only when
        # identical text was checked as multiple identifier types.
        nid = f"query:{key}" if len(types) <= 1 else f"typed-query:{qt}:{key}"
        if nid not in seen:
            seen.add(nid)
            nodes.append({
                "id": nid,
                "labels": ["Query", _neo4j_label(qt)],
                "properties": {"value": q, "query_type": qt, "depth": int(depth or 0)},
            })
        return nid

    def site_node(f: Finding) -> str:
        sid = str(f.site_id or f.site or "unknown")
        nid = f"site:{sid}"
        if nid not in seen:
            seen.add(nid)
            nodes.append({
                "id": nid,
                "labels": ["Site"],
                "properties": {
                    "name": str(f.site or sid),
                    "site_id": sid,
                    "category": str(f.category or "misc"),
                    "tags": [str(t) for t in (f.tags or [])],
                    "nsfw": bool(f.nsfw),
                },
            })
        return nid

    core = ("status", "url", "confidence", "method", "source", "depth", "http_status", "elapsed", "error", "ts", "query_type",
            "upstream_repositories")
    for v in views:
        qn = query_node(v.query, v.depth, v.query_type)
        rows = v.findings if include_all else v.found
        for f in rows:
            st = _status(f)
            props: dict = {
                "status": st.value,
                "url": f.url,
                "confidence": f.confidence,
                "method": f.method,
                "source": f.source,
                "depth": int(f.depth or 0),
                "http_status": f.http_status,
                "elapsed": f.elapsed,
                "error": f.error,
                "ts": f.ts,
                "query_type": str(f.query_type),
                "upstream_repositories": [r["id"] for r in repository_coverage(f)],
            }
            for k, val in _extra_dict(f.extra).items():
                key = str(k)
                if key in core or val is None or val == "" or val == [] or val == {}:
                    continue
                props[key] = _neo4j_value(val)
            props = {k: val for k, val in props.items() if val is not None}
            edges.append({
                "id": f"e{len(edges) + 1}",
                "type": "FOUND_ON" if st is Status.FOUND else "CHECKED_ON",
                "source": qn,
                "target": site_node(f),
                "properties": props,
            })
    for v in views:
        if v.parent:
            if len(qtypes.get(v.parent, set())) > 1:
                # The saved model has no parent type. Do not invent a relation
                # to one of several different identifiers sharing this text.
                continue
            pn = query_node(v.parent)
            cn = query_node(v.query, v.depth, v.query_type)
            edges.append({
                "id": f"e{len(edges) + 1}",
                "type": "DISCOVERED",
                "source": pn,
                "target": cn,
                "properties": {"depth": int(v.depth or 0)},
            })
    return {
        "format": "consensus-neo4j",
        "version": 1,
        "generator": GENERATOR,
        "generated": time.time(),
        "queries": [v.query for v in views],
        "counts": _counts(summary.findings or []),
        "nodes": nodes,
        "edges": edges,
        "cypher_import": NEO4J_CYPHER_IMPORT,
    }


def render_neo4j(summary: ScanSummary, include_all: bool = False) -> str:
    return _json_dumps(build_neo4j(summary, include_all)) + "\n"


# --------------------------------------------------------------------------- html
_jinja_env = None


def _env():
    global _jinja_env
    if _jinja_env is None:
        from jinja2 import Environment, FileSystemLoader

        _jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,          # everything rendered comes from scanned pages
            trim_blocks=True,
            lstrip_blocks=True,
        )
    return _jinja_env


def _card(f: Finding) -> dict:
    """Template-ready view of one finding (all values pre-sanitised strings)."""
    from .continuity import observation_time
    st = _status(f)
    elapsed = ""
    if f.elapsed is not None:
        try:
            elapsed = f"{float(f.elapsed):.1f}s"
        except (TypeError, ValueError):
            elapsed = ""
    fields, diagnostics = split_fields(f.extra)
    detail_count = len(enrichment_fields(f))
    label, reason, tone = assessment(f)
    link_url, link_label = result_link(f)
    return {
        "site": str(f.site or f.site_id or "?"),
        "site_id": str(f.site_id or ""),
        "category": str(f.category or "misc"),
        "status": st.value,
        "status_label": st.label,
        "url": _safe_http_url(f.url),
        "url_text": _clean_text(str(f.url), 300) if f.url else "",
        "result_url": link_url,
        "link_label": link_label,
        "information_source": information_source(f),
        "coverage_text": coverage_text(f),
        "avatar": _avatar_url(f.extra) if st is Status.FOUND else None,
        "fields": display_fields(fields, limit=0, include_images=True),
        "field_heading": _field_heading(f),
        "diagnostics": display_fields(diagnostics, limit=0, include_images=True),
        "assessment": label,
        "reason": reason,
        "observed_at": observation_time(f),
        "analyst_review": f.extra.get("_analyst_review"),
        "tone": tone,
        "has_details": bool(detail_count),
        "detail_count": detail_count,
        "informational": f.category in INFO_CATEGORIES,
        "source": str(f.source or ""),
        "method": str(f.method or ""),
        "elapsed": elapsed,
        "error": _clean_text(str(f.error), 200) if f.error else "",
        "http_status": f.http_status,
        "tags": [str(t) for t in (f.tags or [])][:6],
        "nsfw": bool(f.nsfw),
        "loud": bool(f.loud),
        "repositories": repository_coverage(f),
    }


def build_html_context(summary: ScanSummary, include_all: bool = False) -> dict:
    from .breach_review import breach_review

    views = group_by_query(summary)
    facts = _facts(summary, views)
    compared = comparisons(summary)
    per_query = {(r["query"], r["query_type"]): r for r in compared["per_query"]}
    queries = []
    for v in views:
        matches = [f for f in v.found if f.category not in INFO_CATEGORIES]
        information = [f for f in v.findings if f.category in INFO_CATEGORIES]
        others = [f for f in v.others if f.category not in INFO_CATEGORIES]
        queries.append({
            "query": v.query,
            "query_type": v.query_type,
            "parent": v.parent,
            "depth": v.depth,
            "found_count": len(matches),
            "total": len(v.findings),
            "counts": v.counts(),
            "comparison": per_query[(v.query, v.query_type)],
            "cards": [_card(f) for f in sorted(matches, key=lambda f: (not has_details(f), str(f.site).casefold()))],
            "information": [_card(f) for f in information],
            "others": [_card(f) for f in others] if include_all else [],
        })
    top = [q["query"] for q in queries if not q["parent"]] or [q["query"] for q in queries]
    return {
        "title": "Consensus report — " + _clean_text(", ".join(top), 80) if top else "Consensus report",
        "facts": facts,
        "identity": report_identity(),
        "breaches": breach_review(summary),
        "coverage_legend": LEGEND,
        "comparisons": compared,
        "queries": queries,
        "include_all": bool(include_all),
        "changes": summary.options.get("changes"),
        "investigation": summary.options.get("investigation"),
        "categories": sorted({str(f.category or "misc") for v in views for f in v.findings
                              if include_all or _status(f) is Status.FOUND or f.category in INFO_CATEGORIES}),
        "options": [(str(k), _compact(val, 200)) for k, val in redact_options(summary.options).items()],
    }


def render_html(summary: ScanSummary, include_all: bool = False) -> str:
    """Self-contained HTML page (inline CSS, no external assets, autoescaped)."""
    template = _env().get_template(HTML_TEMPLATE)
    from .tool_logos import report_logos

    return template.render(**build_html_context(summary, include_all), tool_logos=report_logos(summary.findings))


# --------------------------------------------------------------------------- pdf
PDF_HINT = "PDF export needs: pip install consensus-osint[pdf]"

_PDF_FONT_CANDIDATES = [
    ("DejaVuSans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    ("DejaVuSans", "/usr/share/fonts/TTF/DejaVuSans.ttf"),
    ("DejaVuSans", "/usr/share/fonts/dejavu/DejaVuSans.ttf"),
    ("ArialUnicode", "/Library/Fonts/Arial Unicode.ttf"),
    ("ArialUnicode", "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
    ("Arial", "C:/Windows/Fonts/arial.ttf"),
]


def _pdf_font() -> str:
    """Register a Unicode TTF when one exists so non-Latin names render; else Helvetica."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    for name, path in _PDF_FONT_CANDIDATES:
        if not Path(path).exists():
            continue
        try:
            if name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(name, path))
            return name
        except Exception:  # noqa: BLE001 - unreadable font, try the next one
            continue
    return "Helvetica"


def render_pdf(summary: ScanSummary, include_all: bool = False) -> bytes:
    """Simple reportlab document: title, summary table, per-query table of found sites."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError(PDF_HINT) from exc

    font = _pdf_font()
    pdf_font = pdfmetrics.getFont(font)
    glyphs = getattr(pdf_font.face, "charToGlyph", None)
    checked_characters: set[str] = set()
    views = group_by_query(summary)
    facts = _facts(summary, views)

    base = ParagraphStyle("base", fontName=font, fontSize=8.5, leading=11, wordWrap="CJK")
    small = ParagraphStyle("small", parent=base, fontSize=7.5, leading=9.5, textColor=colors.HexColor("#555555"))
    head = ParagraphStyle("head", parent=base, textColor=colors.HexColor("#333333"))
    h1 = ParagraphStyle("h1", parent=base, fontSize=18, leading=22, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=base, fontSize=13, leading=16, spaceBefore=14, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=base, fontSize=10, leading=13, spaceBefore=10, spaceAfter=4,
                        textColor=colors.HexColor("#444444"))

    def esc(value: Any, limit: int = 0) -> str:
        text = _clean_text(str(value if value is not None else ""), limit)
        for char in set(text) - checked_characters:
            if char.isspace():
                continue
            supported = (bool(glyphs.get(ord(char))) if glyphs is not None else
                         all(run_font is pdf_font for run_font, _ in pdfmetrics.unicode2T1(char, [pdf_font])))
            if not supported:
                raise ValueError(f"PDF font {font} cannot render U+{ord(char):04X}. "
                                 "Save as HTML to preserve the text; use your browser's Print to save a PDF.")
        checked_characters.update(text)
        return _html.escape(text, quote=True)

    def P(text: str, style=base):
        return Paragraph(text, style)

    def table(rows: list, widths: list):
        t = Table(rows, colWidths=widths, repeatRows=1, splitInRow=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9ecef")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f7f9")]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8ccd2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm,
        title="Consensus report", author=GENERATOR, subject=facts["queries"],
    )
    w = doc.width
    logo_panel = Image(str(TEMPLATES_DIR / "consensus-report-wordmark.png"), width=224, height=56)
    logo_panel.hAlign = "LEFT"
    story: list = [
        logo_panel,
        P("Consensus report", h1),
        P(esc(SLOGAN), h2),
        P(esc(DESCRIPTION)),
        P(esc(UPDATE_NOTE)),
        P(esc("By " + ORGANIZATION)),
        P("<br/>".join(esc(url) for _, url in LINKS), small),
        P(esc(HEALTH_WARNING), small),
        P(esc(LEGEND), small),
        P(f"Generated {esc(facts['generated'])} by {esc(facts['generator'])}", small),
        Spacer(1, 8),
    ]
    rows = [[P("Query", head), P("Type", head), P("Positive signals", head), P("Checked", head), P("Discovered via", head)]]
    for v in views:
        rows.append([P(esc(v.query, 120)), P(esc(v.query_type)), P(_n(len(v.found))), P(_n(len(v.findings))),
                     P(esc(v.parent or "", 120))])
    story.append(table(rows, [w * 0.32, w * 0.14, w * 0.12, w * 0.12, w * 0.30]))
    run = [f"started {facts['started']}"] if facts["started"] else []
    if facts["duration"]:
        run.append(f"duration {facts['duration']}")
    run.append(f"checks {facts['checks']}")
    story.append(Spacer(1, 5))
    story.append(P("Run: " + esc(" · ".join(run)), small))
    story.append(P("Recorded outcomes: " + esc(facts["counts_line"]), small))

    for v in views:
        story.append(P(f"{esc(v.query, 150)} <font color='#666666'>({esc(v.query_type)})</font>", h2))
        if v.parent:
            story.append(P(f"Discovered via {esc(v.parent, 150)} (depth {v.depth})", small))
        if not v.found:
            story.append(P("No positive lookup signals.", base))
        else:
            rows = [[P("Site", head), P("Category", head), P("URL", head), P("Details", head), P("Tools with this lookup", head)]]
            for cat, items in v.by_category():
                for f in items:
                    label, explanation, _ = assessment(f)
                    lines = [esc(label), esc(explanation), "Observed: " + esc(observation_time(f))]
                    if f.error:
                        lines.append(esc(f.error))
                    details = display_fields(split_fields(f.extra)[0], limit=0, include_images=True)
                    if details:
                        lines.append(esc(_field_heading(f)))
                    for df in details:
                        lines.append(f"{esc(df.label)}: {esc(df.value)}")
                    rows.append([P(esc(f.site or f.site_id, 80)), P(esc(cat, 40)),
                                 P(esc(f.url or "", 400)), P("<br/>".join(lines)),
                                 P(esc(coverage_text(f)).replace("\n", "<br/>"))])
            story.append(table(rows, [w * 0.15, w * 0.10, w * 0.22, w * 0.35, w * 0.18]))
        if include_all and v.others:
            story.append(P(f"Other results ({_n(len(v.others))})", h3))
            rows = [[P("Site", head), P("Status", head), P("URL", head), P("Note", head), P("Tools with this lookup", head)]]
            for f in v.others:
                label, explanation, _ = assessment(f)
                notes = [esc(explanation), "Observed: " + esc(observation_time(f))]
                if f.error:
                    notes.append(esc(f.error))
                if f.http_status:
                    notes.append(f"HTTP {f.http_status}")
                details = display_fields(split_fields(f.extra)[0], limit=0, include_images=True)
                if details:
                    notes.append(esc(_field_heading(f)))
                    notes.extend(f"{esc(df.label)}: {esc(df.value)}" for df in details)
                rows.append([P(esc(f.site or f.site_id, 80)), P(esc(label)),
                             P(esc(f.url or "", 400)), P("<br/>".join(notes)),
                             P(esc(coverage_text(f)).replace("\n", "<br/>"))])
            story.append(table(rows, [w * 0.18, w * 0.12, w * 0.24, w * 0.28, w * 0.18]))

    story.append(P("Commands to run next", h2))
    for label, command in MENU:
        story.append(P(esc(label + ": " + command)))
    doc.build(story)
    return buf.getvalue()


# --------------------------------------------------------------------------- xmind
_XMAP_NS = "urn:xmind:xmap:xmlns:content:2.0"
_XLINK_NS = "http://www.w3.org/1999/xlink"
_XMANIFEST_NS = "urn:xmind:xmap:xmlns:manifest:1.0"


def _xmind_topic(title: Any, href: str | None = None, labels: list | None = None,
                 children: list | None = None, notes: str | None = None) -> dict:
    full_title = _clean_text(str(title)) or "?"
    caption = full_title
    if len(full_title) > 200:
        caption = full_title[:175].rstrip() + " [full value in notes]"
        notes = full_title + ("\n\n" + str(notes) if notes else "")
    t: dict = {"id": uuid.uuid4().hex, "class": "topic", "title": caption}
    if href:
        t["href"] = href
    if labels:
        t["labels"] = [_clean_text(str(lb), 100) for lb in labels if lb]
    if notes:
        t["notes"] = {"plain": {"content": _clean_text(str(notes))}}
    if children:
        t["children"] = {"attached": children}
    return t


def build_xmind_sheet(summary: ScanSummary, include_all: bool = False) -> dict:
    """Mind map: scan -> query -> category -> site -> metadata (XMind Zen JSON shape)."""
    views = group_by_query(summary)
    facts = _facts(summary, views)
    qtopics = []
    for v in views:
        kids = []
        for cat, items in v.by_category():
            sites = []
            for f in items:
                meta = [_xmind_topic(f"{df.label}: {df.value}")
                        for df in display_fields(split_fields(f.extra)[0], limit=0, include_images=True)]
                label, explanation, _ = assessment(f)
                meta.insert(0, _xmind_topic("Result: " + label,
                                            notes=explanation + ("\n" + str(f.error) if f.error else "")))
                meta.append(_xmind_topic("Tools with this lookup", notes=coverage_text(f) + "\n" + LEGEND))
                conf = _confidence_text(f)
                sites.append(_xmind_topic(f.site or f.site_id, href=_safe_http_url(f.url),
                                          labels=[conf] if conf else None, children=meta,
                                          notes=f.url if f.url and not _safe_http_url(f.url) else None))
            kids.append(_xmind_topic(f"{cat} ({_n(len(items))})", children=sites))
        if not kids:
            kids.append(_xmind_topic("no positive lookup signals"))
        if include_all and v.others:
            by_status: dict = {}
            for f in v.others:
                by_status.setdefault(_status(f), []).append(f)
            st_topics = [
                _xmind_topic(f"{st.label} ({_n(len(fs))})", children=[
                    _xmind_topic(f.site or f.site_id, href=_safe_http_url(f.url),
                                 notes=assessment(f)[0] + ": " + assessment(f)[1] + "\n" + (f.error or "")
                                       + "\nTools with this lookup:\n" + coverage_text(f) + "\n" + LEGEND,
                                 children=[_xmind_topic(_field_heading(f), children=[
                                     _xmind_topic(f"{df.label}: {df.value}") for df in
                                     display_fields(split_fields(f.extra)[0], limit=0, include_images=True)
                                 ])] if split_fields(f.extra)[0] else []) for f in fs
                ])
                for st, fs in by_status.items()
            ]
            kids.append(_xmind_topic(f"other results ({_n(len(v.others))})", children=st_topics))
        qtopics.append(_xmind_topic(v.title, labels=[f"discovered via {v.parent}"] if v.parent else None,
                                    children=kids))
    root = _xmind_topic("Consensus: " + (facts["queries"] or "report"),
                        notes=f"{facts['generator']} · {facts['generated']} · {facts['counts_line']}\nBy {ORGANIZATION}\n"
                              + SLOGAN + "\n" + DESCRIPTION + "\n" + UPDATE_NOTE + "\n"
                              + "\n".join(url for _, url in LINKS) + "\n" + HEALTH_WARNING,
                        children=qtopics or [_xmind_topic("no queries")])
    return {"id": uuid.uuid4().hex, "class": "sheet", "title": "Consensus report", "rootTopic": root}


def _xmind_xml_topic(parent: ET.Element, t: dict) -> None:
    el = ET.SubElement(parent, f"{{{_XMAP_NS}}}topic", {"id": t["id"]})
    if t.get("href"):
        el.set(f"{{{_XLINK_NS}}}href", t["href"])
    ET.SubElement(el, f"{{{_XMAP_NS}}}title").text = t["title"]
    if t.get("labels"):
        labels = ET.SubElement(el, f"{{{_XMAP_NS}}}labels")
        for lb in t["labels"]:
            ET.SubElement(labels, f"{{{_XMAP_NS}}}label").text = lb
    if t.get("notes"):
        notes = ET.SubElement(el, f"{{{_XMAP_NS}}}notes")
        ET.SubElement(notes, f"{{{_XMAP_NS}}}plain").text = t["notes"]["plain"]["content"]
    kids = (t.get("children") or {}).get("attached") or []
    if kids:
        ch = ET.SubElement(el, f"{{{_XMAP_NS}}}children")
        topics = ET.SubElement(ch, f"{{{_XMAP_NS}}}topics", {"type": "attached"})
        for k in kids:
            _xmind_xml_topic(topics, k)


def _xmind_content_xml(sheet: dict) -> bytes:
    ET.register_namespace("", _XMAP_NS)
    ET.register_namespace("xlink", _XLINK_NS)
    root = ET.Element(f"{{{_XMAP_NS}}}xmap-content", {"version": "2.0", "timestamp": str(int(time.time() * 1000))})
    sh = ET.SubElement(root, f"{{{_XMAP_NS}}}sheet", {"id": sheet["id"]})
    _xmind_xml_topic(sh, sheet["rootTopic"])
    ET.SubElement(sh, f"{{{_XMAP_NS}}}title").text = sheet["title"]
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _xmind_manifest_xml(names: list) -> bytes:
    ET.register_namespace("", _XMANIFEST_NS)
    root = ET.Element(f"{{{_XMANIFEST_NS}}}manifest", {"password-hint": ""})
    for n in names:
        media = "text/xml" if n.endswith(".xml") else "application/json" if n.endswith(".json") else ""
        ET.SubElement(root, f"{{{_XMANIFEST_NS}}}file-entry", {"full-path": n, "media-type": media})
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def render_xmind(summary: ScanSummary, include_all: bool = False) -> bytes:
    """``.xmind`` archive readable by XMind 8 (content.xml) and XMind Zen/2020+ (content.json)."""
    sheet = build_xmind_sheet(summary, include_all)
    ver = _html.escape(str(__version__), quote=True)
    meta_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
        '<meta xmlns="urn:xmind:xmap:xmlns:meta:2.0" version="2.0">'
        f"<Creator><Name>consensus-osint</Name><Version>{ver}</Version></Creator></meta>"
    )
    members = [
        ("content.json", _json_dumps([sheet], indent=None)),
        ("content.xml", _xmind_content_xml(sheet)),
        ("metadata.json", _json_dumps({"creator": {"name": "consensus-osint", "version": str(__version__)}}, indent=None)),
        ("meta.xml", meta_xml),
    ]
    names = [n for n, _ in members]
    members.append(("manifest.json", _json_dumps({"file-entries": {n: {} for n in names}}, indent=None)))
    members.append(("META-INF/manifest.xml", _xmind_manifest_xml(names + ["manifest.json", "META-INF/manifest.xml"])))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


# --------------------------------------------------------------------------- dispatch
_TEXT_RENDERERS = {
    "txt": render_text,
    "md": render_markdown,
    "html": render_html,
    "csv": render_csv,
    "json": render_json,
    "jsonl": render_jsonl,
    "neo4j": render_neo4j,
}


def normalize_format(fmt: str) -> str:
    f = str(fmt or "").strip().lower().lstrip(".")
    f = _FORMAT_ALIASES.get(f, f)
    if f not in FORMATS:
        raise ValueError(f"unknown report format {fmt!r}; supported: {', '.join(FORMATS)}")
    return f


def infer_format(path: str | Path, fmt: str | None = None) -> str:
    """Explicit ``fmt`` wins; otherwise the file extension decides (``x.neo4j.json`` -> neo4j)."""
    if fmt:
        return normalize_format(fmt)
    p = Path(path)
    name = p.name.lower()
    if name.endswith(".graph.html"):
        return "graph-html"
    if name.endswith((".neo4j.json", ".graph.json", ".neo4j")):
        return "neo4j"
    f = _EXT_TO_FORMAT.get(p.suffix.lower())
    if not f:
        raise ValueError(
            f"cannot infer report format from {p.name!r}; end the filename with a known extension such as .html, or choose a format (-f): {', '.join(FORMATS)}"
        )
    return f


def render(summary: ScanSummary, fmt: str, include_all: bool = False) -> str | bytes:
    """Render ``summary`` in ``fmt``: ``str`` for text formats, ``bytes`` for pdf / xmind."""
    f = normalize_format(fmt)
    if f == "graph-html":
        from .graph_report import render_graph
        return render_graph(summary, include_all)
    if f == "pdf":
        return render_pdf(summary, include_all)
    if f == "xmind":
        return render_xmind(summary, include_all)
    return _TEXT_RENDERERS[f](summary, include_all)


def save_report(summary: ScanSummary, path: str | Path, fmt: str | None = None, *,
                include_all: bool = False) -> Path:
    """Write one report; returns the path.  Raises on any failure (the CLI catches)."""
    p = Path(path).expanduser()
    f = infer_format(p, fmt)
    data = render(summary, f, include_all)
    _write_report(p, data)
    return p


def _write_report(p: Path, data: str | bytes) -> None:
    """Keep an existing report intact if writing or replacement fails."""
    p.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=p.parent, prefix=".consensus-", suffix=".tmp", delete=False) as fh:
            temporary = Path(fh.name)
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, p)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


__all__ = [
    "FORMATS",
    "CSV_COLUMNS",
    "PDF_HINT",
    "DisplayField",
    "QueryView",
    "build_html_context",
    "build_json",
    "build_neo4j",
    "build_xmind_sheet",
    "display_fields",
    "group_by_query",
    "infer_format",
    "normalize_format",
    "render",
    "render_csv",
    "render_html",
    "render_json",
    "render_jsonl",
    "render_markdown",
    "render_neo4j",
    "render_pdf",
    "render_text",
    "render_xmind",
    "save_json",
    "save_report",
    "summary_counts_line",
]
