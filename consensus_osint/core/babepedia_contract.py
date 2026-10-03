"""Query-bound title and labelled metadata for the retained profile route."""
import hashlib
import json

from bs4 import BeautifulSoup, Comment

from .mailbox_contracts import http_issue
from .models import Status


def shipped_rule(entry):
    if entry.get("id") != "babepedia":
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == "9ad8993d1ee8c358b8c196d042535835d2259331e98ac27b3bfb347301b86eeb"


def outcome(code, text, query, headers):
    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, {}, reason
    page = BeautifulSoup(text, "html.parser")
    for node in page.select('script, style, template, noscript, [hidden], [aria-hidden="true"]'):
        node.decompose()
    for node in page.find_all(string=lambda value: isinstance(value, Comment)):
        node.extract()
    if page.get_text(" ", strip=True) == "Profile not found":
        return Status.NOT_FOUND, {}, None
    titles = page.find_all("title")
    if len(titles) != 1 or titles[0].get_text(" ", strip=True) != query + "'s Profile":
        return Status.UNKNOWN, {}, "No unique profile title matching the requested username"
    labels = {"account status:": "status", "signed up on:": "signup_date", "last seen on:": "last_seen",
              "logins:": "logins", "views of this page:": "views"}
    values = {key: [] for key in labels.values()}
    for row in page.find_all("tr"):
        cells = row.find_all(["td", "th"], recursive=False)
        if len(cells) != 2:
            continue
        key = labels.get(cells[0].get_text(" ", strip=True).casefold())
        if key:
            values[key].append(cells[1].get_text(" ", strip=True))
    fields = {key: value[0] for key, value in values.items() if len(value) == 1 and value[0]}
    return Status.FOUND, fields, None
