"""Read retained SoundCloud profile hydration without executing JavaScript.

Field mappings follow vendor/user_scanner/user_scan/music/soundcloud.py
(Copyright (c) 2025 Kaif, MIT; see vendor/user_scanner/LICENSE). Permalinks
identify profile routes; the provider's username field is a display name.
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error

MAX_DOCUMENT = 8 * 1024 * 1024


class _Scripts(HTMLParser):
    def __init__(self, document):
        super().__init__(convert_charrefs=True)
        self.scripts, self.ignored = [], []
        self.current = None
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        if tag in ("template", "noscript"):
            self.ignored.append(tag)
        if tag == "script":
            values = dict(attrs)
            eligible = (not self.ignored and len(values) == len(attrs) and "src" not in values
                        and (values.get("type") or "").lower() in ("", "text/javascript", "application/javascript"))
            self.current = [] if eligible else None

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.current is not None:
            self.scripts.append("".join(self.current))
            self.current = None
        if self.ignored and self.ignored[-1] == tag:
            self.ignored.pop()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate hydration field")
        result[key] = value
    return result


def _hydration(document):
    # Skip comments, quoted examples, template strings and regex literals. This
    # recognizes the retained JSON assignment; it is not a JavaScript evaluator.
    quoted = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
    pattern = (r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted
               + r"|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*"
               + r"|(?P<assignment>(?<![\w$.])window\s*\.\s*__sc_hydration\s*=)")
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    arrays = []
    for script in _Scripts(document).scripts:
        for match in re.finditer(pattern, script):
            if match["assignment"] is None:
                continue
            start = match.end()
            while start < len(script) and script[start].isspace():
                start += 1
            value, end = decoder.raw_decode(script, start)
            tail = script[end:].lstrip()
            if not isinstance(value, list) or tail and not tail.startswith(";"):
                raise ValueError("Unsupported hydration assignment")
            arrays.append(value)
    if len(arrays) != 1:
        raise ValueError("Missing or ambiguous hydration")
    return arrays[0]


def _route(url, query):
    if (not isinstance(url, str) or len(url) > 2048
            or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url)):
        return False
    try:
        parts = urlsplit(url)
        return (parts.scheme in ("http", "https") and parts.hostname in ("soundcloud.com", "www.soundcloud.com")
                and parts.port in (None, 443 if parts.scheme == "https" else 80)
                and parts.username is None and parts.password is None
                and not parts.query and not parts.fragment
                and unquote(parts.path).rstrip("/").casefold() == "/" + query.casefold())
    except ValueError:
        return False


def _bound(profile, query):
    if not isinstance(profile, dict) or has_service_error(profile):
        return False
    slug, url = profile.get("permalink"), profile.get("permalink_url")
    if "permalink" in profile and (not isinstance(slug, str) or slug.casefold() != query.casefold()):
        return False
    if "permalink_url" in profile and not _route(url, query):
        return False
    if slug is None and url is None:
        return False
    identity, urn = profile.get("id"), profile.get("urn")
    if "id" in profile and (type(identity) is not int or identity <= 0):
        return False
    if "urn" in profile:
        if not isinstance(urn, str) or not re.fullmatch(r"soundcloud:users:[1-9][0-9]*", urn):
            return False
        if identity is not None and str(identity) != urn.rsplit(":", 1)[1]:
            return False
    return identity is not None or urn is not None


def profile_outcome(document, query):
    unknown = "The page did not provide one SoundCloud profile tied to the requested permalink; account status is unknown."
    if (not isinstance(query, str) or not query or query in (".", "..") or len(query) > 256
            or any(ord(c) <= 32 or ord(c) == 127 or c in "/\\?#" for c in query)):
        return Status.UNKNOWN, {}, unknown
    if not isinstance(document, str) or len(document) > MAX_DOCUMENT:
        return Status.UNKNOWN, {}, "The SoundCloud document exceeded the parser limit; account status is unknown."
    try:
        rows = _hydration(document)
    except (ValueError, RecursionError):
        return Status.UNKNOWN, {}, unknown
    users = []
    for row in rows:
        if not isinstance(row, dict):
            return Status.UNKNOWN, {}, unknown
        if row.get("hydratable") == "user":
            data = row.get("data")
            if not isinstance(data, dict) or has_service_error(row):
                return Status.UNKNOWN, {}, unknown
            if _bound(data, query):
                users.append(data)
    if len(users) != 1:
        return Status.UNKNOWN, {}, unknown
    data = users[0]
    fields = {}
    for source, target in (("id", "id"), ("urn", "urn"), ("full_name", "name"), ("username", "display_name"),
                           ("permalink", "username"), ("permalink_url", "profile_url"), ("description", "bio")):
        value = data.get(source)
        if (source == "id" and type(value) is int) or (isinstance(value, str) and value.strip()):
            fields[target] = value.strip() if isinstance(value, str) else value
    location = [data[key].strip() for key in ("city", "country_code") if isinstance(data.get(key), str) and data[key].strip()]
    if location:
        fields["location"] = ", ".join(location)
    for source, target in (("followers_count", "followers"), ("followings_count", "following"), ("track_count", "tracks"),
                           ("playlist_count", "playlists"), ("likes_count", "likes")):
        value = data.get(source)
        if type(value) is int and value >= 0:
            fields[target] = value
    if type(data.get("verified")) is bool:
        fields["verified"] = data["verified"]
    if isinstance(data.get("avatar_url"), str) and data["avatar_url"].strip():
        fields["media"] = {"avatar": data["avatar_url"].strip()}
    return Status.FOUND, fields, None


def response_outcome(response, query):
    status, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 404))
    if status is not None:
        return status, {}, reason
    if response.status_code == 404:
        # Retain the scoped HTTP404 contract, but never override contradictory
        # profile evidence, a challenge, or a provider failure with absence.
        positive, _, _ = profile_outcome(response.text, query)
        if positive is Status.FOUND:
            return Status.UNKNOWN, {}, "HTTP 404 conflicts with returned SoundCloud profile evidence."
        return Status.NOT_FOUND, {}, None
    return profile_outcome(response.text, query)
