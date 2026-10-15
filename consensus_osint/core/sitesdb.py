"""Unified site database (data-driven username checks).

Loads ``data/sites.json`` (Sherlock / Maigret / nexfil / gosearch / vesper /
findme / linkook derived, MIT & GPL) and ``data/sites_wmn.json`` (WhatsMyName
derived, CC BY-SA 4.0), then applies optional user overrides from
``~/.consensus/sites_overrides.json``::

    {"disable": ["site-id", ...], "enable": ["site-id", ...], "sites": [ {...full entry...} ]}

"""
from __future__ import annotations

import json
import math
import os
import re
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

from .request_templates import (
    content_type,
    graphql_url,
    maigret_uses_username,
    payload_format_for,
    prepare_headers,
    substitute_payload,
    substitute_url,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_FILES = [DATA_DIR / "sites.json", DATA_DIR / "sites_wmn.json", DATA_DIR / "sites_fediverse.json"]

# Reviewed request contracts; overrides cannot make these ambiguous probes valid.
_AUDIT_RESTRICTIONS = MappingProxyType({
    "3dcadforums": 'Unavailable in this release.',
    "amperka": 'Unavailable in this release.',
    "aqa": 'Unavailable in this release.',
    "esportal-com": 'Unavailable in this release.',
    "redtube-channels": 'Unavailable in this release.',
    "redtube-pornstars": 'Unavailable in this release.',
    "site-docin-com": 'Unavailable in this release.',
    "southklad": 'Unavailable in this release.',
    "spotifycommunity": 'Unavailable in this release.',
    "upwork": 'Unavailable in this release.',
    "upwork-upwork-com": 'Unavailable in this release.',
    "zapravdu": 'Unavailable in this release.',
    "magnific": 'Unavailable in this release.',
    "npm-package": 'Unavailable in this release.',
    "codex-wordpress-org": 'Unavailable in this release.',
    "wordpress-com-deleted": 'Unavailable in this release.',
    "hackerrank": 'Unavailable in this release.',
    "bugcrowd": 'Unavailable in this release.',
    "leetcode": 'Unavailable in this release.',
    "leetcode-contest": 'Unavailable in this release.',
    "leetcode-rating": 'Unavailable in this release.',
    "leetcode-cn": 'Unavailable in this release.',

    "en-wikipedia-org": 'Unavailable in this release.',
    "wikipedia": 'Unavailable in this release.',
    "wikipedia-wikipedia-org": 'Unavailable in this release.',

    "lichess-tvs": 'Unavailable in this release.',
    "modrinth": 'Unavailable in this release.',

    "91wan": 'Unavailable in this release.',
    "site-zol-com-cn": 'Unavailable in this release.',
    "site-365car-com-cn": 'Unavailable in this release.',
    "site-dangdang-com": 'Unavailable in this release.',
    "site-iciba-com": 'Unavailable in this release.',
    "site-lizi-com": 'Unavailable in this release.',
    "site-lvmama-com": 'Unavailable in this release.',
    "site-renren-com": 'Unavailable in this release.',
    "site-smzdm-com": 'Unavailable in this release.',
    "figshare": 'Unavailable in this release.',
    "twoplustwo": 'Unavailable in this release.',
})


def user_config_dir() -> Path:
    d = Path(os.environ.get("CONSENSUS_HOME") or Path.home() / ".consensus")
    d.mkdir(parents=True, exist_ok=True)
    return d


def overrides_path() -> Path:
    return user_config_dir() / "sites_overrides.json"


HOSTED_SUFFIXES = ("github.io", "gitlab.io", "netlify.app", "vercel.app", "herokuapp.com",
                   "pages.dev", "web.app", "firebaseapp.com", "azurewebsites.net")


def domain_words(host: str) -> set:
    """The labels of a host that people type: ``github.com`` -> {"github"},
    ``gist.github.com`` -> {"gist", "github"}; the suffix and ``www`` are dropped.
    A site merely *hosted* on a platform keeps only its own name (``camas.github.io``
    -> {"camas"}), so ``--site github`` does not drag in every GitHub Pages tool."""
    host = (host or "").lower()
    for suf in HOSTED_SUFFIXES:
        if host.endswith("." + suf):
            host = host[: -len(suf) - 1] + ".x"
            break
    labels = [x for x in host.split(".") if x]
    if len(labels) >= 2:
        labels = labels[:-1]
    return {x for x in labels if x and x != "www"}


def site_keys(site) -> set:
    """Every name ``--site`` / ``--exclude`` may use for a site: id, display name, domain and its words."""
    domain = (site.domain or "").lower()
    return {site.id, site.name.lower(), domain} | domain_words(domain)


def is_weak_rule(detect: dict | None, regex_check: str | None = None) -> bool:
    """True when a rule can only prove the page loaded, not that the account exists.

    A rule that matches on the HTTP status code alone reports a hit on every site
    that answers 200 for a missing profile (a soft 404), so it is scored and
    reported as weak.  Page markers (``found_strings`` / ``missing_strings``), a
    redirect check (``response_url``) are response evidence. An input-format
    regex says nothing about whether the account exists.

    Derived from the rule itself rather than trusted from the data, so an entry
    from any upstream list is judged on what it can actually prove.
    """
    if not isinstance(detect, dict):
        return True
    if detect.get("type") == "profile_api":
        from .community_profiles import CONTRACTS
        return detect.get("contract") not in CONTRACTS
    if detect.get("found_strings") or detect.get("missing_strings"):
        return False
    types = detect.get("type")
    types = types if isinstance(types, list) else [types]
    return "response_url" not in [t for t in types if t]


PLACEHOLDER_RE = re.compile(r"\{\}|\{username\}|\{account\}|\^USER\^", re.I)


def site_key(url: str) -> str:
    """Normalise a profile-URL pattern into a de-duplication key.

    Two lists describing the same account surface have to collapse into one
    entry, or that site is contacted twice on every scan.  The scheme, a ``www.``
    prefix, a mobile mirror (``m.`` / ``mobile.``), a default port and a trailing
    slash are all cosmetic differences between lists.
    """
    u = PLACEHOLDER_RE.sub("{}", (url or "").strip())
    try:
        parts = urlsplit(u if "://" in u else "//" + u)
    except ValueError:
        return u
    authority = parts.netloc
    userinfo, separator, host = authority.rpartition("@")
    if not separator:
        host = authority
    default = {"http": "80", "https": "443"}.get(parts.scheme.lower())
    if default:
        host = re.sub(":" + default + "$", "", host)
    bare = re.sub(r"^(www|m|mobile)\.", "", host, flags=re.I)
    if "." in bare:  # never reduce a short domain such as m.me to "me"
        host = bare
    # URL paths, query values and credentials can be case-sensitive. Only a
    # trailing path slash is cosmetic here, never a slash inside a query value.
    path = parts.path if parts.query or parts.fragment else parts.path.rstrip("/")
    return ((userinfo + "@" if separator else "") + host.lower() + path
            + ("?" + parts.query if parts.query else "") + ("#" + parts.fragment if parts.fragment else ""))


#: How far each upstream list is trusted when two equally strong rules disagree.
DETECT_PRIORITY = {
    "community": 55,   # human-curated for this project; trusted above most upstream lists
    "wmn": 60,
    "sherlock": 50,
    "maigret": 40,
    "fediverse": 35,   # generated per platform from the Fediverse Observer directory
    "gosearch": 30,
    "vesper": 30,
    "findme": 30,
    "linkook": 30,
    "sherlockv2": 30,
    "bundled": 29,
    "userjoo": 29,
    "detectdee": 25,
    "sreg": 24,
    "nexfil": 10,
    "aliens_eye": 10,
}


def rule_strength(detect: dict | None, regex_check: str | None = None, *,
                  disabled: bool = False, priority: int = 0) -> int:
    """Precedence used to pick one rule when several describe the same site.

    Evidence first: a rule that can actually prove an account exists always beats
    one that can only prove the page loaded, whichever list it came from - a
    marker-based check from an obscure list is worth more than a bare status code
    from a trusted one.  Source trust then breaks ties between equally strong
    rules, and a more specific rule edges out a vaguer one.  A rule already known
    to be broken always loses.
    """
    score = int(priority)
    if disabled:
        score -= 1000
    if not is_weak_rule(detect, regex_check):
        score += 100
    d = detect if isinstance(detect, dict) else {}
    return score + min(len(d.get("found_strings") or []), 3) + min(len(d.get("missing_strings") or []), 3)


def _strength(s) -> int:
    return rule_strength(s.detect, s.regex_check, disabled=s.disabled or bool(s.audit_disabled_reason),
                         priority=DETECT_PRIORITY.get(s.detect_source, 0))


def _request_parts(s) -> tuple:
    headers = {key.lower(): value for key, value in prepare_headers(s.headers, {}, s.payload).items()}
    payload = s.payload
    if isinstance(payload, (dict, list)):
        headers.setdefault("content-type", "application/json")
    media = content_type(headers)
    if isinstance(payload, str) and (media == "application/json" or media.endswith("+json")):
        try:
            payload = json.loads(payload)
        except ValueError:
            pass  # A malformed definition must not alias a valid structured body.
    return tuple(sorted(headers.items())), json.dumps(payload, sort_keys=True, ensure_ascii=True)


def _request_context(s) -> tuple:
    headers, payload = _request_parts(s)
    return s.id_type, s.method.upper(), payload, headers, s.strip_chars, getattr(s, "payload_format", "simple")


def request_key(s) -> tuple:
    """De-duplication key for the request a site entry actually sends.

    One list may put an API endpoint in ``url`` while another keeps the human
    profile page in ``url`` and that same endpoint in ``url_probe``.  Both send
    the identical request, so that is what they are keyed on. Identifier kind,
    method, body, headers and input normalisation remain part of the contract.
    """
    return _request_context(s), site_key(s.url_probe or s.url)


def profile_key(s) -> tuple | None:
    """Recorded account-page identity, separate from a fixed lookup endpoint."""
    # A declared human profile can link different API checks for the same
    # account. A fixed endpoint with a body identifier is not a profile key.
    profile = bool(s.url_probe and site_key(s.url_probe) != site_key(s.url))
    profile |= s.method.upper() in {"GET", "HEAD"} and s.payload is None
    if profile and "{username}" in s.url:
        # Content-Type belongs to the probe body, not to the declared profile.
        headers = tuple((key, value) for key, value in _request_parts(s)[0] if key != "content-type")
        return "profile", s.id_type, s.strip_chars, headers, site_key(s.url)
    return None


def _dedupe_keys(s) -> set:
    keys = {("request", request_key(s))}
    profile = profile_key(s)
    if profile is not None:
        keys.add(profile)
    return keys


def merge_site_metadata(keep, other) -> None:
    'Merge display metadata and source credits without changing the lookup request.'
    keep.sources = sorted({*(keep.sources or []), *(other.sources or [])})
    keep.tags = sorted({*(keep.tags or []), *(other.tags or [])})
    keep.protection = sorted({*(keep.protection or []), *(other.protection or [])})
    keep.nsfw = bool(keep.nsfw or other.nsfw)
    if keep.rank is None or (other.rank is not None and other.rank < keep.rank):
        keep.rank = other.rank
    if keep.category in (None, "", "misc") and other.category not in (None, "", "misc"):
        keep.category = other.category
    for attr in ("url_main", "regex_check", "engine"):
        if not getattr(keep, attr) and getattr(other, attr):
            setattr(keep, attr, getattr(other, attr))
    if not keep.fail_flags and other.fail_flags:
        keep.fail_flags = dict(other.fail_flags)
    keep_is_bare = not keep.url_probe or site_key(keep.url) == site_key(keep.url_probe)
    other_has_page = bool(other.url_probe) and site_key(other.url) != site_key(other.url_probe)
    if keep_is_bare and other_has_page and request_key(keep) == request_key(other):
        keep.url_probe = keep.url_probe or keep.url  # the request does not change ...
        keep.url = other.url                         # ... only the link shown to the user


def dedupe_sites(sites: list) -> list:
    'Combine overlapping lookup requests while preserving source credits.'
    # Two entries are the same check if they show the same profile page OR send the
    # same request; either alone misses cases the other catches.  Both keys of a
    # group point at its current survivor.
    survivor_of: dict = {}
    groups: list = []
    for s in sites:
        keys = _dedupe_keys(s)
        hits: list = []
        for k in keys:
            v = survivor_of.get(k)
            if v is not None and all(v is not h for h in hits):
                hits.append(v)
        if not hits:
            groups.append(s)
            for k in keys:
                survivor_of[k] = s
            continue
        # Everything that touched either key is one site - including two groups this
        # entry happens to bridge.  Fold them all into the strongest; on a tie the
        # entry seen first keeps its place.
        members = hits + [s]
        winner = max(members, key=_strength)
        for m in members:
            if m is not winner:
                merge_site_metadata(winner, m)
        first = next((i for i, g in enumerate(groups) if any(g is m for m in members)), len(groups))
        groups = [g for g in groups if not any(g is m for m in members)]
        groups.insert(first, winner)
        losers = {id(m) for m in members if m is not winner}
        for k, v in list(survivor_of.items()):
            if id(v) in losers:
                survivor_of[k] = winner
        for k in keys | _dedupe_keys(winner):
            survivor_of[k] = winner
    return groups


@dataclass
class Site:
    id: str
    name: str
    url: str
    url_main: str = ""
    url_probe: str | None = None
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    payload: object = None
    follow_redirects: bool = True
    strip_chars: str = ""
    detect: dict = field(default_factory=dict)
    regex_check: str | None = None
    tags: list = field(default_factory=list)
    category: str = "misc"
    nsfw: bool = False
    rank: int | None = None
    protection: list = field(default_factory=list)
    id_type: str = "username"
    disabled: bool = False
    disabled_reason: str | None = None
    ignore_403: bool = False
    fail_flags: dict = field(default_factory=dict)
    encoding: str | None = None
    protocol: str | None = None
    engine: str | None = None
    sources: list = field(default_factory=list)
    detect_source: str = ""
    weak: bool = False
    payload_format: str = "simple"

    _regex = None

    @classmethod
    def from_dict(cls, d: dict) -> Site:
        if not isinstance(d, dict) or not all(isinstance(d.get(k), str) and d[k] for k in ("id", "name", "url")):
            raise TypeError("site requires nonempty string id, name and url")
        if "detect" in d and not isinstance(d["detect"], dict):
            raise TypeError("site detect must be an object")
        if d.get("url_probe") is not None and not isinstance(d["url_probe"], str):
            raise TypeError("site url_probe must be a string")
        for key in ("tags", "protection", "sources"):
            if key in d and (not isinstance(d[key], list) or any(not isinstance(x, str) for x in d[key])):
                raise TypeError(f"site {key} must be a list of strings")
        for key in ("method", "strip_chars", "category", "id_type", "detect_source", "url_main"):
            if key in d and not isinstance(d[key], str):
                raise TypeError(f"site {key} must be a string")
        for key in ("regex_check", "disabled_reason", "encoding", "protocol", "engine"):
            if d.get(key) is not None and not isinstance(d[key], str):
                raise TypeError(f"site {key} must be a string or null")
        for key in ("follow_redirects", "nsfw", "disabled", "ignore_403", "weak"):
            if key in d and not isinstance(d[key], bool):
                raise TypeError(f"site {key} must be a boolean")
        if d.get("rank") is not None and (isinstance(d["rank"], bool) or not isinstance(d["rank"], (int, float))
                                          or isinstance(d["rank"], float) and not math.isfinite(d["rank"])):
            raise TypeError("site rank must be numeric or null")
        if not isinstance(d.get("fail_flags", {}), dict):
            raise TypeError("site fail_flags must be an object")
        headers = d.get("headers", {})
        payload_format = payload_format_for(d)
        if payload_format not in ("simple", "maigret"):
            raise TypeError("site payload_format must be simple or maigret")
        if not isinstance(headers, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
            raise TypeError("site headers must contain string keys and values")
        detect = d.get("detect", {})
        types = detect.get("type")
        types = types if isinstance(types, list) else [types]
        if any(t is not None and t not in ("status_code", "message", "response_url", "wmn", "profile_api") for t in types):
            raise TypeError("site detect.type must be one of status_code, message, response_url, wmn, profile_api")
        if "profile_api" in types:
            from .community_profiles import CONTRACTS
            if types != ["profile_api"] or detect.get("contract") not in CONTRACTS:
                raise TypeError("profile_api requires one supported community contract")
        for key in ("found_strings", "missing_strings"):
            if key in detect and (not isinstance(detect[key], list) or any(not isinstance(x, str) for x in detect[key])):
                raise TypeError(f"site detect.{key} must be a list of strings")
        for key in ("found_status", "missing_status"):
            if detect.get(key) is not None and (not isinstance(detect[key], list) or any(type(x) is not int or not 100 <= x <= 599 for x in detect[key])):
                raise TypeError(f"site detect.{key} must be a list of HTTP status codes")
        known = {f for f in cls.__dataclass_fields__ if not f.startswith("_")}
        site = cls(**{k: v for k, v in d.items() if k in known})
        site.detect = dict(site.detect)
        site.payload_format = payload_format
        if site.payload_format == "maigret" and not isinstance(site.payload, dict):
            raise TypeError("site maigret payload must be an object")
        # Retained Sreg definitions were imported without their original form
        # media type. Its upstream POST implementation uses requests data=.
        if site.detect_source == "sreg" and isinstance(site.payload, dict) and not any(
                key.lower() == "content-type" for key in site.headers):
            site.headers = {**site.headers, "Content-Type": "application/x-www-form-urlencoded"}
        # Judge the rule on what it can prove, whatever the data claims, so a
        # database built by any version stays honest about status-code-only rules.
        if not site.weak and is_weak_rule(site.detect, site.regex_check):
            site.weak = True
        # A request that never mentions the username answers the same for everyone,
        # so it can only ever produce a false positive or a false negative.
        # blank markers (a lone space from an upstream list) would match every page
        for _k in ("found_strings", "missing_strings"):
            _v = site.detect.get(_k) if isinstance(site.detect, dict) else None
            if isinstance(_v, list):
                site.detect[_k] = [x for x in _v if isinstance(x, str) and x.strip()]

        payload_part = json.dumps(site.payload or "")
        if site.payload_format == "maigret" and not maigret_uses_username(site.payload):
            payload_part = ""
        request_parts = " ".join((site.url_probe or site.url or "", payload_part,
                                  json.dumps(site.headers or {})))
        if not site.disabled and "{username}" not in request_parts:
            site.disabled = True
            site.disabled_reason = "the request does not include the username"
        return site

    def to_dict(self) -> dict:
        result = {k: getattr(self, k) for k in self.__dataclass_fields__ if not k.startswith("_")}
        result.update(effective_disabled=self.effective_disabled,
                      audit_disabled_reason=self.audit_disabled_reason)
        return result

    # ------------------------------------------------------------------ helpers
    @property
    def audit_disabled_reason(self) -> str | None:
        if reason := _AUDIT_RESTRICTIONS.get(self.id):
            return reason
        markers = [marker for key in ("found_strings", "missing_strings")
                   for marker in (self.detect.get(key) or [])]
        if any(isinstance(marker, str) and marker.strip().casefold() == "temp_fix_2022_wiki_value"
               for marker in markers):
            return "Unsupported catalogue rule: temporary wiki placeholder is not account evidence"
        return None

    @property
    def effective_disabled(self) -> bool:
        """Catalogue/user setting plus non-overridable request-contract holds."""
        return self.disabled or bool(self.audit_disabled_reason)

    @property
    def domain(self) -> str:
        m = re.match(r"https?://([^/]+)", self.url.replace("{username}", "x"))
        host = (m.group(1) if m else "").lower()
        return re.sub(r"^www\.", "", host)

    def normalise_username(self, username: str) -> str:
        # Keep reviewed handles intact when refreshed upstream data strips characters.
        if self.id in ("medium-medium-com", "omg-lol", "livejournal", "tumblr-tumblr-com"):
            from .profile_api_contracts import catalogue_scope
            if catalogue_scope(self) == self.id:
                return username
        u = username
        for ch in self.strip_chars or "":
            u = u.replace(ch, "")
        return u

    def username_allowed(self, username: str) -> bool:
        if not self.regex_check:
            return True
        if self._regex is None:
            try:
                self._regex = re.compile(self.regex_check)
            except re.error:
                self._regex = re.compile("(?!)")
        return self._regex.search(username) is not None

    def profile_url(self, username: str) -> str:
        return substitute_url(self.url, {"username": self.normalise_username(username)})

    def probe_url(self, username: str) -> str:
        tpl = self.url_probe or self.url
        return substitute_url(tpl, {"username": self.normalise_username(username)})

    def build_body(self, username: str):
        """Return (data, json) for the request body."""
        if self.payload is None:
            return None, None
        body = substitute_payload(self.payload, {"username": self.normalise_username(username)}, self.headers,
                                  graphql=graphql_url(self.url_probe or self.url), payload_format=self.payload_format)
        explicit_form = any(key.lower() == "content-type" for key in self.headers) and content_type(self.headers) == "application/x-www-form-urlencoded"
        if isinstance(self.payload, str) or explicit_form:
            return body, None
        return None, body

    def build_headers(self, username: str) -> dict:
        return prepare_headers(self.headers, {"username": self.normalise_username(username)}, self.payload)

    @property
    def needs_impersonation(self) -> bool:
        return any(p in ("tls_fingerprint", "cf_js_challenge", "cf_firewall", "datadome") for p in self.protection)


class SiteDB:
    def __init__(self, sites: Iterable[Site]):
        self.sites: list = list(sites)
        self._by_id = {s.id: s for s in self.sites}

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, files: list | None = None, apply_overrides: bool = True) -> SiteDB:
        sites: list = []
        for path in DEFAULT_FILES if files is None else files:
            path = Path(path)
            if not path.exists():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            entries = data["sites"] if isinstance(data, dict) else data
            if not isinstance(entries, list):
                raise ValueError(f"{path}: sites must be an array")
            for e in entries:
                try:
                    sites.append(Site.from_dict(e))
                except TypeError:
                    continue
        db = cls(dedupe_sites(sites))
        if apply_overrides:
            db.apply_overrides()
        return db

    def apply_overrides(self, path: Path | None = None) -> None:
        p = Path(path) if path else overrides_path()
        if not p.exists():
            return
        try:
            ov = _read_overrides(p)
        except Exception:  # noqa: BLE001
            return
        for e in ov.get("sites", []):
            try:
                s = Site.from_dict(e)
            except TypeError:
                continue
            if s.id in self._by_id:
                self.sites[self.sites.index(self._by_id[s.id])] = s
            else:
                self.sites.append(s)
            self._by_id[s.id] = s

        for sid in ov.get("disable", []):
            s = self._by_id.get(sid)
            if s:
                s.disabled = True
                reason = ov.get("reasons", {}).get(sid, "disabled on this computer")
                s.disabled_reason = f"{reason} (switch back on with: consensus sites enable {sid})"
        for sid in ov.get("enable", []):
            s = self._by_id.get(sid)
            if s:
                s.disabled = False
                s.disabled_reason = None

    # ------------------------------------------------------------------ queries
    def get(self, key: str) -> Site | None:
        k = key.strip().lower()
        if k in self._by_id:
            return self._by_id[k]
        for s in self.sites:
            if s.name.lower() == k or s.domain == k or s.domain == re.sub(r"^www\.", "", k):
                return s
        return None

    def select(
        self,
        *,
        ids: Iterable[str] | None = None,
        exclude: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
        exclude_tags: Iterable[str] | None = None,
        include_nsfw: bool = False,
        include_disabled: bool = False,
        top: int | None = None,
        id_type: str = "username",
        sources: Iterable[str] | None = None,
        tor: bool = False,
    ) -> list:
        out = []
        want = {i.strip().lower() for i in ids} if ids else None
        skip = {i.strip().lower() for i in exclude} if exclude else set()
        tagset = {t.strip().lower() for t in tags} if tags else None
        xtags = {t.strip().lower() for t in exclude_tags} if exclude_tags else set()
        srcset = {s.strip().lower() for s in sources} if sources else None
        for s in self.sites:
            keys = site_keys(s)
            if want is not None and not (keys & want):
                continue
            if keys & skip:
                continue
            if s.id_type != id_type:
                continue
            if s.audit_disabled_reason and not include_disabled and want is None:
                continue
            if s.disabled and not include_disabled and want is None:
                continue
            if s.nsfw and not include_nsfw and want is None:
                continue
            if s.protocol == "tor" and not tor:
                continue
            if s.protocol in ("i2p", "dns"):
                continue
            if tagset is not None and not (set(s.tags) & tagset or s.category in tagset):
                continue
            if xtags and (set(s.tags) & xtags or s.category in xtags):
                continue
            if srcset is not None and not (set(s.sources) & srcset):
                continue
            out.append(s)
        if top:
            out.sort(key=lambda s: (s.rank if s.rank else 10**9, -len(s.sources), s.id))
            out = out[:top]
        return out

    def id_types(self) -> list:
        return sorted({s.id_type for s in self.sites})

    def all_tags(self) -> dict:
        counts: dict = {}
        for s in self.sites:
            for t in set(s.tags) | {s.category}:
                counts[t] = counts.get(t, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def stats(self) -> dict:
        return {
            "sites": len(self.sites),
            "enabled": sum(1 for s in self.sites if not s.effective_disabled),
            "disabled": sum(1 for s in self.sites if s.effective_disabled),
            "audit_restricted": sum(1 for s in self.sites if s.audit_disabled_reason),
            "nsfw": sum(1 for s in self.sites if s.nsfw),
            "sources": sorted({src for s in self.sites for src in s.sources}),
        }

    def __len__(self) -> int:
        return len(self.sites)


def _read_overrides(path: Path) -> dict:
    ov = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(ov, dict):
        raise ValueError("overrides must be an object")
    for key in ("disable", "enable"):
        values = ov.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError(f"overrides {key} must be a list of strings")
    if not isinstance(ov.get("reasons", {}), dict) or not isinstance(ov.get("sites", []), list):
        raise ValueError("overrides reasons must be an object and sites must be a list")
    return ov


def overrides_disabled_ids(path: Path | None = None) -> set:
    'Return site and module IDs disabled by the user.'
    p = Path(path) if path else overrides_path()
    if not p.exists():
        return set()
    try:
        ov = _read_overrides(p)
    except Exception:  # noqa: BLE001
        return set()
    return {str(x) for x in ov.get("disable", [])} - {str(x) for x in ov.get("enable", [])}


def save_override(disable: list | None = None, enable: list | None = None, reasons: dict | None = None) -> Path:
    "Save the user's enabled and disabled lookup preferences."
    p = overrides_path()
    ov = {"disable": [], "enable": [], "reasons": {}, "sites": []}
    if p.exists():
        # Refuse to overwrite malformed user data; repair it explicitly first.
        ov.update(_read_overrides(p))
    dis = set(ov.get("disable", []))
    en = set(ov.get("enable", []))
    for sid in disable or []:
        dis.add(sid)
        en.discard(sid)
    for sid in enable or []:
        en.add(sid)
        dis.discard(sid)
    ov["disable"] = sorted(dis)
    ov["enable"] = sorted(en)
    # A reason describes one decision: drop it when the site is switched back on or disabled again for
    # another cause, so the displayed reason always describes the current setting.
    kept = {sid: why for sid, why in ov.get("reasons", {}).items()
            if sid in dis and sid not in (disable or []) and sid not in (enable or [])}
    ov["reasons"] = {**kept, **{sid: why for sid, why in (reasons or {}).items() if sid in dis}}
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".overrides-", suffix=".json", dir=p.parent)
    pending = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(ov, indent=1))
        pending.replace(p)
    finally:
        pending.unlink(missing_ok=True)
    return p
