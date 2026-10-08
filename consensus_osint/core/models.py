"""Unified data model shared by every checker, module adapter and report.

Every upstream tool has its own idea of a "result" (Sherlock QueryResult,
Maigret MaigretCheckResult, holehe dicts, user-scanner Result, socialscan
PlatformResponse ...).  Consensus normalises all of them into :class:`Finding`
so reports, recursion and confidence scoring only ever deal with one shape.
"""
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from typing import Any
from urllib.parse import unquote_plus


class Status(str, Enum):
    """Outcome of a single check."""

    FOUND = "found"            # account / registration confirmed
    NOT_FOUND = "not_found"    # site answered and the identifier is free / unknown there
    UNKNOWN = "unknown"        # site answered but the answer is ambiguous
    BLOCKED = "blocked"        # WAF / captcha / bot protection / 403
    RATE_LIMITED = "rate_limited"
    ERROR = "error"            # network error, timeout, exception
    SKIPPED = "skipped"        # filtered (regex mismatch, disabled, NSFW, loud, ...)

    @property
    def is_positive(self) -> bool:
        return self is Status.FOUND

    @property
    def is_definitive(self) -> bool:
        return self in (Status.FOUND, Status.NOT_FOUND)

    @property
    def label(self) -> str:
        return {
            Status.FOUND: "FOUND",
            Status.NOT_FOUND: "not found",
            Status.UNKNOWN: "unknown",
            Status.BLOCKED: "blocked",
            Status.RATE_LIMITED: "rate limited",
            Status.ERROR: "error",
            Status.SKIPPED: "skipped",
        }[self]


# categories of informational rows (number/address analysis, dork links) that are
# always displayed but never counted as "found accounts"
INFO_CATEGORIES = ("analysis", "dorks")


class QueryType(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    # Maigret-style special identifier types discovered during recursion
    OTHER = "other"

    @classmethod
    def detect(cls, query: str) -> QueryType:
        """Guess the identifier type of a raw query string."""
        q = query.strip()
        if q.lower().startswith("tel:"):
            return cls.PHONE
        if "@" in q and "." in q.split("@")[-1]:
            return cls.EMAIL
        digits = q.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").replace(".", "")
        if q.startswith("+") and digits[1:].isdigit() and len(digits) >= 8:
            return cls.PHONE
        if digits.isdigit() and len(digits) >= 9:
            return cls.PHONE
        return cls.USERNAME

    @classmethod
    def split_typed(cls, text: str) -> tuple[str, str | None]:
        """Separate an optional ``username:``/``user:``/``email:``/``phone:`` prefix.

        Returns ``(identifier, type or None)``.  The prefix states the type where
        detection would guess wrongly, such as an all-digit username.
        """
        prefix, separator, value = text.strip().partition(":")
        kind = {"username": cls.USERNAME, "user": cls.USERNAME, "email": cls.EMAIL,
                "phone": cls.PHONE}.get(prefix.strip().lower()) if separator else None
        return (value.strip(), kind.value) if kind else (text.strip(), None)


@dataclass
class Finding:
    """One normalised check result."""

    query: str
    query_type: str                      # QueryType value or a Maigret id type ("yandex_public_id" ...)
    site: str                            # display name
    site_id: str                         # stable slug
    status: Status
    url: str | None = None            # profile URL (or the site's main URL for email/phone checks)
    category: str = "misc"
    tags: list = field(default_factory=list)
    source: str = "sites-db"             # which merged project/module family produced it
    method: str | None = None         # detection technique
    confidence: float | None = None   # 0..1 (None = not scored)
    extra: dict = field(default_factory=dict)   # scraped metadata: name, bio, avatar, ids, emails, phones, links...
    error: str | None = None
    http_status: int | None = None
    elapsed: float | None = None
    loud: bool = False                   # the check may notify the target (password reset e-mails etc.)
    nsfw: bool = False
    depth: int = 0                       # recursion depth at which the finding was produced
    parent: str | None = None         # query that led to this one (recursion)
    ts: float = field(default_factory=time.time)

    # ------------------------------------------------------------------ helpers
    def __post_init__(self) -> None:
        if isinstance(self.query_type, QueryType):
            self.query_type = self.query_type.value
        try:
            self.status = Status(self.status)
        except (ValueError, TypeError):
            self.status = Status.UNKNOWN
        if not isinstance(self.extra, dict):
            self.extra = {} if self.extra is None else {"data": self.extra}
        self.extra = as_json_safe(self.extra)
        # Errors can embed transport URLs; credentials are never finding data.
        for name in ("error", "url"):
            value = getattr(self, name)
            if isinstance(value, str):
                setattr(self, name, _redact_url_passwords(value))

    @property
    def found(self) -> bool:
        return self.status is Status.FOUND

    def to_dict(self) -> dict:
        from .continuity import observation_time
        from .presentation import assessment
        from .provenance import repository_coverage

        result = as_json_safe(self)
        result["upstream_repositories"] = repository_coverage(self)
        label, explanation, _ = assessment(self)
        result["evidence"] = {"assessment": label, "explanation": explanation, "observed_at": observation_time(self)}
        return result

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        """Rebuild a finding from a saved report; tolerant of values written by another
        version or edited by hand. Unknown statuses become UNKNOWN, while invalid
        identity or numeric fields raise a descriptive ValueError at the boundary."""
        if not isinstance(d, dict):
            raise ValueError("finding must be an object")
        d = dict(d)
        for name in ("query", "query_type", "site", "site_id"):
            if name not in d:
                raise ValueError(f"finding is missing required field '{name}'")
            if not isinstance(d[name], str):
                raise ValueError(f"finding '{name}' must be a string")
        for name in ("category", "source"):
            if name in d and not isinstance(d[name], str):
                raise ValueError(f"finding '{name}' must be a string")
        for name in ("url", "method", "error", "parent"):
            if d.get(name) is not None and not isinstance(d[name], str):
                raise ValueError(f"finding '{name}' must be a string or null")
        for name in ("confidence", "elapsed", "ts"):
            if name not in d or (d[name] is None and name != "ts"):
                continue
            value = d[name]
            try:
                finite = not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError(f"finding '{name}' must be a finite number")
            if name == "confidence" and not 0 <= value <= 1:
                raise ValueError("finding 'confidence' must be between 0 and 1")
            if name == "elapsed" and value < 0:
                raise ValueError("finding 'elapsed' must be nonnegative")
        for name in ("depth", "http_status"):
            if name not in d or (d[name] is None and name == "http_status"):
                continue
            value = d[name]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"finding '{name}' must be an integer")
            if name == "depth" and value < 0:
                raise ValueError("finding 'depth' must be nonnegative")
            if name == "http_status" and value != 0 and not 100 <= value <= 599:
                raise ValueError("finding 'http_status' must be 0 (no response) or between 100 and 599")
        for name in ("loud", "nsfw"):
            if name in d and not isinstance(d[name], bool):
                raise ValueError(f"finding '{name}' must be a boolean")
        try:
            status = d.get("status")
            # A hand-edited "FOUND" is still a match; only a word with no meaning here becomes unknown.
            d["status"] = Status(status.strip().lower() if isinstance(status, str) else status)
        except (ValueError, TypeError):
            d["status"] = Status.UNKNOWN
        known = {f.name for f in fields(cls)}
        d = {k: v for k, v in d.items() if k in known}
        if not isinstance(d.get("extra"), dict):
            d["extra"] = {} if d.get("extra") is None else {"data": d["extra"]}
        if not isinstance(d.get("tags"), list):
            d["tags"] = [] if d.get("tags") is None else [str(d["tags"])]
        return cls(**d)

    # convenience constructors -------------------------------------------------
    @classmethod
    def error_result(cls, query: str, query_type: str, site: str, site_id: str, error: str, **kw) -> Finding:
        return cls(query=query, query_type=query_type, site=site, site_id=site_id, status=Status.ERROR,
                   error=_redact_url_passwords(str(error))[:300], **kw)

    @classmethod
    def skipped(cls, query: str, query_type: str, site: str, site_id: str, reason: str, **kw) -> Finding:
        return cls(query=query, query_type=query_type, site=site, site_id=site_id, status=Status.SKIPPED, error=reason, **kw)


@dataclass
class ScanSummary:
    """Aggregate of one scan run (possibly recursive)."""

    queries: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    started: float = field(default_factory=time.time)
    finished: float | None = None
    options: dict = field(default_factory=dict)

    @property
    def found(self) -> list:
        """Positive account / exposure findings (local analysis rows excluded)."""
        return [f for f in self.findings if f.status is Status.FOUND and f.category not in INFO_CATEGORIES]

    def counts(self) -> dict:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f.status.value] = c.get(f.status.value, 0) + 1
        return c

    def to_dict(self) -> dict:
        return as_json_safe({
            "queries": self.queries,
            "started": self.started,
            "finished": self.finished,
            "options": redact_options(self.options),
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        })


def dedupe_findings(findings: list) -> list:
    """Collapse duplicate checks while retaining separate search-result URLs."""
    order = {
        Status.FOUND: 0,
        Status.NOT_FOUND: 1,
        Status.UNKNOWN: 2,
        Status.BLOCKED: 3,
        Status.RATE_LIMITED: 4,
        Status.ERROR: 5,
        Status.SKIPPED: 6,
    }
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.query, f.query_type, f.site_id)
        if f.source == "search-engines":
            # Search engines use a host-level site ID; several returned pages
            # at that host remain distinct evidence throughout final exports.
            key += (f.url,)
        cur = best.get(key)
        if cur is None or order[f.status] < order[cur.status] or (
            order[f.status] == order[cur.status] and len(f.extra) > len(cur.extra)
        ):
            best[key] = f
    return list(best.values())


def as_json_safe(obj: Any) -> Any:
    """Copy metadata into strict JSON values, masking credentials throughout.

    Bytes decode as UTF-8 with replacement, nonfinite floats become null, and
    cycles/depth beyond 64 levels get explicit markers. Unknown objects get a
    type marker instead of invoking arbitrary string/deepcopy hooks. Source
    findings and metadata are never mutated.
    """
    active: set[int] = set()

    def key_text(key):
        if isinstance(key, Enum):
            return key_text(key.value)
        if isinstance(key, str):
            return key
        if key is None or isinstance(key, (bool, int, float)):
            try:
                return str(key)
            except ValueError:
                return "[integer too large]"
        return f"[unsupported {type(key).__name__} key]"

    def clean(value, secret=False, depth=0):
        if depth > 64:
            return "[maximum depth]"
        if isinstance(value, Enum):
            return clean(value.value, secret, depth + 1)
        structured = isinstance(value, (dict, list, tuple, set, frozenset)) or (
            is_dataclass(value) and not isinstance(value, type))
        if structured:
            if id(value) in active:
                return "[circular]"
            active.add(id(value))
            try:
                if isinstance(value, dict):
                    return {_redact_url_passwords(key_text(k)): clean(v, secret or _secret_key(key_text(k)), depth + 1)
                            for k, v in value.items()}
                if is_dataclass(value):
                    return {f.name: clean(getattr(value, f.name), secret or _secret_key(f.name), depth + 1)
                            for f in fields(value)}
                return [clean(v, secret, depth + 1) for v in value]
            finally:
                active.remove(id(value))
        if secret:
            return value if value is None or (isinstance(value, str) and value == "") else "***"
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            return _redact_url_passwords(value)
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                str(value)  # respect the interpreter's integer/JSON digit limit
            except ValueError:
                return "[integer too large]"
            return value
        if value is None or isinstance(value, bool):
            return value
        return f"[unsupported {type(value).__name__}]"

    return clean(obj)


_SECRET_WORDS = frozenset(("key", "keys", "token", "tokens", "secret", "secrets", "password", "passwords",
                           "passwd", "auth", "authentication", "authorization", "oauth", "cookie", "cookies", "credential", "credentials"))
_URL_CRED_RE = re.compile(r"(://[^:/@]*:)([^@/]+)(@)")
_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"']+")
_QUERY_VALUE_RE = re.compile(r"([?&#])([^=&#]+)=([^&#]*)")


def _secret_key(key: str) -> bool:
    # Recognise separated/camelCase credential names without masking ordinary
    # metadata such as author, keyboard, monkey, or Keybase.
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    tokens = re.split(r"[^a-z0-9]+", words)
    return bool(_SECRET_WORDS.intersection(tokens)) or words in {
        "apikey", "accesskey", "accesstoken", "authtoken", "api_hash", "apihash",
    }


def _redact_url_passwords(value: str) -> str:
    """Mask URI passwords and credential query parameters in URLs or errors."""
    def clean_url(match):
        def clean_parameter(parameter):
            if _secret_key(unquote_plus(parameter[2])):
                return f"{parameter[1]}{parameter[2]}=***"
            return parameter[0]
        return _QUERY_VALUE_RE.sub(clean_parameter, match[0])

    return _URL_RE.sub(clean_url, _URL_CRED_RE.sub(r"\1***\3", value))


def redact_options(options) -> dict:
    """Scan options safe to write anywhere: no proxy password, no API key.

    A proxy URL keeps its host and user with the password replaced.  Anything
    stored under a key that looks like a credential - or anywhere beneath such a
    key, so a whole ``keys`` mapping is covered - is fully masked.
    Ordinary values are preserved through the same JSON-safe conversion used
    for findings, so a report still says how the scan was run.
    """
    return as_json_safe(options) if isinstance(options, dict) else {}
