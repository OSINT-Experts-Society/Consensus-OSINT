"""Profile-heading evidence for the shipped OpenStreetMap rule."""
import hashlib
import json
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Comment

from .mailbox_contracts import http_issue
from .models import Status
from .named_user_contracts import _url


def shipped_rule(entry):
    if entry.get("id") != "openstreetmap":
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == "d67960b34ebe9395d8c173be0316bbca49f4db37959f01884df306b0fe7f575b"


def outcome(code, text, query, headers):
    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, {}, reason
    unknown = Status.UNKNOWN, {}, "No unique OpenStreetMap profile heading matching the requested display name"
    page = BeautifulSoup(text, "html.parser")
    for node in page.select('script, style, template, noscript, [hidden], [aria-hidden="true"]'):
        node.decompose()
    for node in page.find_all(string=lambda value: isinstance(value, Comment)):
        node.extract()
    headings = page.find_all("h1")
    if len(headings) != 1 or headings[0].get_text(" ", strip=True) != query:
        return unknown
    section = headings[0].find_parent(class_="row")
    if section is None:
        return unknown
    dates = []
    for term in section.select("dl.list-inline > dt"):
        if term.get_text(" ", strip=True).rstrip(":").casefold() != "mapper since":
            continue
        value = term.find_next_sibling()
        if value is None or value.name != "dd" or not value.get_text(" ", strip=True):
            return unknown
        dates.append(value.get_text(" ", strip=True))
    if len(dates) != 1:
        return unknown
    extra = {"joined": dates[0]}
    avatars = section.select("img.user_image")
    if len(avatars) == 1:
        source = avatars[0].get("src")
        if isinstance(source, str) and source and not any(ord(c) <= 32 or c == "\\" for c in source):
            try:
                avatar = _url(urljoin("https://www.openstreetmap.org/", source))
            except ValueError:
                avatar = None
            if avatar:
                extra["Avatar"] = avatar
    return Status.FOUND, extra, None
