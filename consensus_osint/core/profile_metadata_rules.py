"""URL-bound metadata for exact shipped public-profile rules."""
import hashlib
import json
import re
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit

from bs4 import BeautifulSoup, Comment

from .mailbox_contracts import http_issue
from .models import Status

_HASHES = {"about_me": "bc9aca3dda804d982240f3a5d3ce029a9961dedde7fdd7d47a84d1c995fda74f",
           "bandcamp": "80e11722ddcff9a5c1f0262af0b1fc0989c9d144e192ee83ca9572374ce2560f",
           "linkedin-us": "50c372a82ac51d95cd929f104b0793c7d426fc750cb7c4a141c8b35f1d433082"}


class _MetadataAttributes(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.head = False
        self.inert = []
        self.ambiguous = False

    def handle_starttag(self, tag, attrs):
        if tag == "head":
            self.head = True
        if tag in ("template", "noscript", "script", "style"):
            self.inert.append(tag)
        if not self.head or self.inert or tag not in ("link", "meta"):
            return
        relevant = (tag == "link" and any(key == "rel" and "canonical" in (value or "").split() for key, value in attrs)
                    or tag == "meta" and any(key == "property" and value in ("og:url", "og:type") for key, value in attrs))
        keys = [key for key, _ in attrs if key in ("rel", "href", "property", "content")]
        if relevant and len(keys) != len(set(keys)):
            self.ambiguous = True

    def handle_endtag(self, tag):
        if self.inert and tag == self.inert[-1]:
            self.inert.pop()
        if tag == "head":
            self.head = False


def shipped_rule(entry):
    expected = _HASHES.get(entry.get("id"))
    if expected is None:
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == expected


def _bound(value, kind, query):
    if not isinstance(value, str) or not value or any(ord(c) <= 32 or c == "\\" for c in value):
        return False
    base = {"about_me": "https://about.me/", "bandcamp": "https://bandcamp.com/"}.get(kind, "https://www.linkedin.com/")
    try:
        url = urlsplit(urljoin(base, value))
        if kind == "about_me":
            hosts = url.hostname in ("about.me", "www.about.me")
        elif kind == "bandcamp":
            hosts = url.hostname == "bandcamp.com"
        else:
            hosts = bool(re.fullmatch(r"(?:www|[a-z]{2})\.linkedin\.com", url.hostname or ""))
        path = "/in/" + query if kind == "linkedin-us" else "/" + query
        return (hosts and url.scheme == "https" and url.port in (None, 443) and url.username is None
                and url.password is None and not url.query and not url.fragment
                and unquote(url.path).rstrip("/") == path)
    except ValueError:
        return False


def outcome(kind, code, text, query, headers):
    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, {}, reason
    unknown = Status.UNKNOWN, {}, "Profile metadata does not identify the requested URL"
    attributes = _MetadataAttributes()
    attributes.feed(text)
    attributes.close()
    if attributes.ambiguous:
        return unknown
    page = BeautifulSoup(text, "html.parser")
    for node in page.select('script, style, template, noscript, [hidden], [aria-hidden="true"]'):
        node.decompose()
    for node in page.find_all(string=lambda value: isinstance(value, Comment)):
        node.extract()
    heads = page.find_all("head")
    if len(heads) != 1:
        return unknown
    head = heads[0]
    canonical = head.select('link[rel~="canonical"]')
    og_urls = head.select('meta[property="og:url"]')
    if len(canonical) > 1 or len(og_urls) > 1 or not (canonical or og_urls):
        return unknown
    urls = [node.get("href") for node in canonical] + [node.get("content") for node in og_urls]
    if not all(_bound(value, kind, query) for value in urls):
        return unknown
    if kind in ("about_me", "bandcamp"):
        titles = head.find_all("title")
        pattern = r".+ \| about\.me" if kind == "about_me" else r".+ collection \| Bandcamp"
        if len(titles) != 1 or not re.fullmatch(pattern, titles[0].get_text(" ", strip=True)):
            return unknown
        return Status.FOUND, {}, None
    types = head.select('meta[property="og:type"]')
    if len(types) != 1 or types[0].get("content") != "profile":
        return unknown
    counts = set(re.findall(r"([\d,]+)\+? connections on LinkedIn", page.get_text(" ", strip=True)))
    fields = {"connections": counts.pop()} if len(counts) == 1 else {}
    return Status.FOUND, fields, None
