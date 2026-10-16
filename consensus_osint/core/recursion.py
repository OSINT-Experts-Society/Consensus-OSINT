"""Recursive / cross scan: mine the metadata of found profiles for *new*
identifiers and scan those too.

Sources of pivots (ideas merged from Maigret's recursive search, user-scanner's
cross-scan and linkook's linked-account discovery):

* fields named username / nickname / handle / login inside ``Finding.extra``
  (socid-extractor output, user-scanner scrapers, Gravatar profiles ...)
* Maigret-style special identifiers (``yandex_public_id``, ``steam_id`` ...)
  which are scanned only against sites that accept that id type
* e-mail addresses anywhere in the metadata
* URLs in the metadata (links, accounts, website ...) that match a known site's
  profile URL template -> (site, username)
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from .models import INFO_CATEGORIES, Finding, QueryType, Status
from .sitesdb import SiteDB

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>\]\)]+", re.I)
HANDLE_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")
USERNAME_KEYS = ("username", "nickname", "handle", "login", "screen_name", "user", "preferredusername", "preferred_username", "alias", "tiktok_username", "twitch_username", "github_username", "gitlab_username", "instagram_username", "twitter_username", "reddit_username")
ID_KEY_RE = re.compile(r"^(?P<type>[a-z0-9]+_(?:id|uid|userid|uguid))$")
RESERVED_SEGMENTS = {"settings", "login", "signup", "register", "search", "explore", "about", "help", "terms", "privacy",
                     "channel", "watch", "user", "users", "u", "in", "p", "tag", "hashtag", "status", "share", "home",
                     "www", "http", "https", "index", "profile", "profiles", "account", "accounts", "api", "static"}
HASH_RE = re.compile(r"^[0-9a-f]{24,64}$", re.I)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
NOREPLY_RE = re.compile(r"(noreply|no-reply|postmaster|mailer-daemon|example\.com|users\.noreply\.github\.com|localhost)", re.I)


@dataclass
class Pivots:
    usernames: set = field(default_factory=set)
    emails: set = field(default_factory=set)
    ids: dict = field(default_factory=dict)        # id_type -> set of values
    links: dict = field(default_factory=dict)      # url -> (site_id, username)
    provenance: dict = field(default_factory=dict) # value -> "site name"

    def add_username(self, u: str, src: str) -> None:
        u = u.strip().lstrip("@")
        if not HANDLE_RE.match(u) or u.lower() in RESERVED_SEGMENTS or u.isdigit():
            return
        if HASH_RE.match(u) or UUID_RE.match(u) or len(u) > 32:
            return  # md5/sha hashes, uuids and long tokens are ids, not handles
        self.usernames.add(u)
        self.provenance.setdefault(u, src)

    def add_email(self, e: str, src: str) -> None:
        e = e.strip()
        if EMAIL_RE.fullmatch(e) and not NOREPLY_RE.search(e):
            self.emails.add(e)
            self.provenance.setdefault(e, src)


class LinkMatcher:
    """Match profile URL components, never fetch a page-supplied destination.

    Query ordering and tracking parameters do not change account identity, but
    duplicated parameters, credentials and sibling navigation routes are not
    unambiguous profile evidence.
    """

    def __init__(self, db: SiteDB):
        self._patterns = []
        self._reserved = {}
        for s in db.sites:
            if s.disabled or s.audit_disabled_reason:
                continue
            if s.id_type != "username" or s.url.count("{username}") != 1:
                continue
            try:
                parts = self._parts(s.url.replace("{username}", "consensus-user-placeholder"))
                if parts is None:
                    continue
                host, port, path, query = parts
                token = "consensus-user-placeholder"
                host = self._host(host) if token not in host else host
                def pattern(value, token=token):
                    return re.compile(re.escape(value).replace(re.escape(token), r"(?P<u>[A-Za-z0-9_.\-]{2,60})"), re.I)
                first = path.strip("/").split("/", 1)[0]
                if token not in host and first and token not in first:
                    self._reserved.setdefault(host, set()).add(first.casefold())
                weight = len(s.url) - len("{username}")
                self._patterns.append((weight, s, pattern(host), port, pattern(path),
                                       {key: pattern(value) for key, value in query.items()}, token in host))
            except (ValueError, re.error):
                continue
        self._patterns.sort(key=lambda row: (-row[0], row[1].id))

    @staticmethod
    def _host(host):
        return re.sub(r"^(www|m|mobile)\.", "", host, flags=re.I)

    @staticmethod
    def _parts(url):
        if (not isinstance(url, str) or not url or "\\" in url
                or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url)):
            return None
        parts = urlsplit(url if "://" in url else "https://" + url)
        if (parts.scheme not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None
                or "%" in parts.hostname or parts.netloc.endswith(":")):
            return None
        if re.search(r"%(?:2f|5c|3f|23|0[0-9a-f]|1[0-9a-f]|7f)", parts.path, re.I):
            return None  # Encoded separators must not change the template's structure.
        port = parts.port
        if port == (443 if parts.scheme == "https" else 80):
            port = None
        path = unquote(parts.path, errors="strict").rstrip("/")
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False,
                          errors="strict", max_num_fields=64)
        if len(dict(pairs)) != len(pairs):
            return None
        return parts.hostname.lower(), port, path, dict(pairs)

    def match(self, url: str) -> tuple | None:
        try:
            parts = self._parts(url)
        except (ValueError, UnicodeError):
            return None
        if parts is None:
            return None
        host, port, path, query = parts
        for _, site, host_rx, expected_port, path_rx, query_rules, subdomain in self._patterns:
            if port != expected_port:
                continue
            matches = [host_rx.fullmatch(host if subdomain else self._host(host)), path_rx.fullmatch(path)]
            matches += [rx.fullmatch(query[key]) if key in query else None for key, rx in query_rules.items()]
            if not all(matches):
                continue
            names = [match.group("u") for match in matches if "u" in match.re.groupindex]
            if len(names) != 1:
                continue
            name = names[0]
            if ((subdomain and "." in name) or name in (".", "..") or name.casefold() in RESERVED_SEGMENTS
                    or name.casefold() in self._reserved.get(self._host(host), set())):
                continue
            return site, name
        return None


def _walk(obj, depth: int = 0):
    """Yield (key, value) leaves of nested metadata."""
    if depth > 4:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).startswith("_"):
                continue  # Request diagnostics and internal state are not profile evidence.
            if isinstance(v, (dict, list)):
                yield from _walk(v, depth + 1)
            else:
                yield str(k), v
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                yield from _walk(v, depth + 1)
            else:
                yield "", v


def extract_pivots(findings: Iterable[Finding], matcher: LinkMatcher | None = None, *, known: Iterable[str] = (),
                   known_queries: Iterable[tuple[str, str]] = ()) -> Pivots:
    """Exclude known text globally, or known query pairs only within their type."""
    piv = Pivots()
    known_values = set(known)
    typed = set(known_queries)
    known_usernames = known_values | {q for q, kind in typed if kind == QueryType.USERNAME.value}
    known_emails = known_values | {q for q, kind in typed if kind == QueryType.EMAIL.value}
    for f in findings:
        if (f.status is not Status.FOUND or not f.extra or f.category in INFO_CATEGORIES
                or (f.confidence is not None and f.confidence < 0.5)):
            continue
        src = f.site
        for key, val in _walk(f.extra):
            if val is None:
                continue
            sval = str(val)
            kl = key.lower()
            if kl in USERNAME_KEYS and sval not in known_usernames:
                piv.add_username(sval, src)
            m = ID_KEY_RE.match(kl)
            if m and sval and len(sval) < 64:
                piv.ids.setdefault(m.group("type"), set()).add(sval)
            for e in EMAIL_RE.findall(sval):
                if e not in known_emails:
                    piv.add_email(e, src)
            if matcher is not None:
                urls = [sval] if sval.startswith(("http://", "https://")) else URL_RE.findall(sval)
                for u in urls:
                    res = matcher.match(u)
                    if res:
                        site, uname = res
                        if uname not in known_usernames and uname.lower() not in RESERVED_SEGMENTS:
                            piv.links[u] = (site.id, uname)
                            piv.add_username(uname, f"{src} -> {site.name}")
    piv.usernames = {u for u in piv.usernames if u not in known_usernames}
    return piv


def plan_next_queries(piv: Pivots, *, max_new: int = 10, include_emails: bool = True,
                      known_id_types: Iterable[str] | None = None) -> list:
    """Return [(query, QueryType|id_type, provenance)] limited to ``max_new`` items.

    ``known_id_types`` restricts special identifiers to the types the site
    database can actually search (``steam_id``, ``yandex_public_id`` ...)."""
    out = []
    if max_new <= 0:
        return out
    for u in sorted(piv.usernames, key=lambda x: (len(x), x))[:max_new]:
        out.append((u, QueryType.USERNAME.value, piv.provenance.get(u, "")))
    if include_emails:
        for e in sorted(piv.emails)[:max_new]:
            out.append((e, QueryType.EMAIL.value, piv.provenance.get(e, "")))
    allowed = set(known_id_types) if known_id_types is not None else None
    for id_type, values in sorted(piv.ids.items()):
        if allowed is not None and id_type not in allowed:
            continue
        for v in sorted(values)[:3]:
            out.append((v, id_type, "metadata"))
    return out[:max_new]
