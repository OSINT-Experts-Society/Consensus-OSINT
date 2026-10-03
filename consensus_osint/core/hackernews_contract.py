"""Identity evidence from the retained Hacker News user-page route."""
import hashlib
import json
import re

from bs4 import BeautifulSoup, Comment

from .mailbox_contracts import http_issue
from .models import Status


def shipped_rule(entry):
    if entry.get("id") != "hackernews":
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == "e6f6252026de81ed3bf10a2bbb74cb0fa3e36160a1fa35077d0c3d5f76360d84"


def outcome(code, text, query, headers):
    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, {}, reason
    unknown = Status.UNKNOWN, {}, "No unique Hacker News profile table matching the requested username"
    page = BeautifulSoup(text, "html.parser")
    for node in page.select('script, style, template, noscript, [hidden], [aria-hidden="true"]'):
        node.decompose()
    for node in page.find_all(string=lambda value: isinstance(value, Comment)):
        node.extract()
    user_rows = []
    for row in page.find_all("tr"):
        cells = row.find_all("td", recursive=False)
        if len(cells) == 2 and cells[0].get_text(" ", strip=True) == "user:":
            user_rows.append((row, cells[1]))
    if not user_rows:
        if page.get_text(" ", strip=True) == "No such user.":
            return Status.NOT_FOUND, {}, None
        return unknown
    if len(user_rows) != 1 or user_rows[0][1].get_text(" ", strip=True) != query:
        return unknown
    table = user_rows[0][0].find_parent("table")
    if table is None:
        return unknown
    fields = {}
    for row in table.find_all("tr"):
        if row.find_parent("table") is not table:
            continue
        cells = row.find_all("td", recursive=False)
        if len(cells) != 2:
            continue
        label = cells[0].get_text(" ", strip=True)
        if label not in ("created:", "karma:", "about:"):
            continue
        if label in fields:
            return unknown
        fields[label] = cells[1].get_text(" ", strip=True)
    if not fields.get("created:"):
        return unknown
    extra = {"joined": fields["created:"]}
    if re.fullmatch(r"-?\d{1,12}", fields.get("karma:", "")):
        extra["karma"] = int(fields["karma:"])
    if fields.get("about:"):
        extra["bio"] = fields["about:"]
    return Status.FOUND, extra, None
