"""Scope reputation-page evidence to a phone number without optional parsers."""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from html import escape
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import phonenumbers

_PHONE = re.compile(r"(?<!\w)\+?[0-9][0-9\s().-]{5,}[0-9](?!\w)")
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_IGNORE = {"nav", "aside", "footer", "form", "button", "select", "option", "style", "noscript", "template", "svg"}


def _numbers(text: str, region: str | None) -> set[str]:
    out = set()
    for match in _PHONE.finditer(text):
        try:
            value = match.group()
            if value.startswith("00"):
                value = "+" + value[2:]
            number = phonenumbers.parse(value, region)
            if phonenumbers.is_possible_number(number):
                out.add(phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164))
        except phonenumbers.NumberParseException:
            continue
    return out


@dataclass(eq=False)
class _Node:
    tag: str
    attrs: dict = field(default_factory=dict)
    parent: _Node | None = None
    children: list = field(default_factory=list)
    excluded: bool = False

    def text(self) -> str:
        return " ".join(c.text() if isinstance(c, _Node) else c for c in self.children
                        if not isinstance(c, _Node) or (c.tag != "script" and not _ignored(c)))

    def render(self) -> str:
        if self.tag == "script":
            return ""
        attrs = "".join(f' {escape(k)}="{escape(v or "", quote=True)}"' for k, v in self.attrs.items())
        content = "".join(c.render() if isinstance(c, _Node) else escape(c) for c in self.children)
        return f"<{self.tag}{attrs}>{content}</{self.tag}>" if self.tag else content


class _Page(HTMLParser):
    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.root = _Node("")
        self.stack = [self.root]
        self.nodes = []
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        if len(self.stack) > 100 or len(self.nodes) >= 20000:
            raise ValueError("reputation page exceeds structural limits")
        node = _Node(tag, dict(attrs), self.stack[-1])
        self.stack[-1].children.append(node)
        self.nodes.append(node)
        if tag not in _VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self.stack[-1].tag == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def _ignored(node: _Node) -> bool:
    attrs = node.attrs
    roles = {"navigation", "complementary", "contentinfo", "search", "menu", "listbox"}
    labels = ((attrs.get("id") or "") + " " + (attrs.get("class") or "")).lower()
    hidden_style = re.search(r"(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!important\s*)?(?:;|$)",
                             attrs.get("style") or "", re.I)
    return bool(node.tag in _IGNORE or "hidden" in attrs or "inert" in attrs or hidden_style
            or (attrs.get("aria-hidden") or "").lower() == "true"
            or (attrs.get("role") or "").lower() in roles
            or bool(re.search(r"\b(?:related|similar|suggested|other)[-_ ](?:numbers?|phones?)\b", labels)))


def _visible(node: _Node) -> bool:
    while node:
        if node.excluded or _ignored(node):
            return False
        node = node.parent
    return True


def _clean(node: _Node, number: str, region: str | None) -> set[str]:
    kept = []
    numbers: set[str] = set()
    for child in node.children:
        if isinstance(child, _Node):
            if _ignored(child):
                child.excluded = True
                continue
            child_numbers = _clean(child, number, region)
            if child.tag in ("section", "article", "div", "li") and child_numbers and number not in child_numbers:
                child.excluded = True
                continue
            numbers.update(child_numbers)
        kept.append(child)
    node.children = kept
    if node.tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
        numbers.update(_numbers(node.text(), region))
    return numbers


def _same_url(value, url: str) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        a, b = urlsplit(urljoin(url, value)), urlsplit(url)
        return (a.scheme, a.netloc.lower(), a.path.rstrip("/"), a.query) == (b.scheme, b.netloc.lower(), b.path.rstrip("/"), b.query)
    except ValueError:
        return False


def _schema_types(obj: dict) -> set[str]:
    types = obj.get("@type", [])
    if isinstance(types, str):
        types = [types]
    if not isinstance(types, list) or any(not isinstance(t, str) for t in types):
        return {"invalid"}
    return {t.rsplit("/", 1)[-1].rsplit(":", 1)[-1] for t in types}


def _bound(obj: dict, number: str, region: str | None, url: str) -> bool:
    if _schema_types(obj) & {"invalid", "WebSite", "Organization", "SoftwareApplication"}:
        return False
    signals = []
    for key in ("name", "telephone"):
        value = obj.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, str):
            numbers = _numbers(value, region)
            if numbers:
                signals.append(numbers == {number})
            elif key == "telephone":
                signals.append(False)
        elif key == "telephone":
            signals.append(False)
    for key in ("url", "@id"):
        if key in obj:
            signals.append(_same_url(obj[key], url))
    return bool(signals) and all(signals)


def _count(value) -> int | None:
    if type(value) is int and 0 <= value <= 10**12:
        return value
    if type(value) is float and math.isfinite(value) and value.is_integer() and 0 <= value <= 10**12:
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,13}", value) and int(value) <= 10**12:
        return int(value)
    return None


def _ratings(page: _Page, number: str, region: str | None, url: str) -> tuple[dict, str | None]:
    out: dict = {}
    issue = None
    for node in page.nodes:
        if node.tag != "script" or (node.attrs.get("type") or "").lower() != "application/ld+json" or not _visible(node):
            continue
        try:
            data = json.loads("".join(c for c in node.children if isinstance(c, str)))
        except (ValueError, RecursionError):
            continue
        pending = [(data, 0)]
        visited = 0
        while pending:
            obj, depth = pending.pop()
            visited += 1
            if depth > 30 or visited > 2000:
                issue = "structured reputation data exceeds structural limits"
                break
            if isinstance(obj, list):
                pending.extend((item, depth + 1) for item in obj)
                continue
            if not isinstance(obj, dict):
                continue
            pending.extend((obj[k], depth + 1) for k in ("@graph", "mainEntity") if k in obj)
            agg = obj.get("aggregateRating")
            subject = obj
            if "AggregateRating" in _schema_types(obj):
                agg, subject = obj, obj.get("itemReviewed")
            if not isinstance(subject, dict) or not _bound(subject, number, region, url) or agg is None:
                continue
            if not isinstance(agg, dict):
                issue = "malformed rating metadata for the queried number"
                continue
            candidate = {}
            for key, name in (("ratingCount", "rating_count"), ("reviewCount", "review_count")):
                if key in agg:
                    value = _count(agg[key])
                    if value is None:
                        issue = "invalid review or rating count for the queried number"
                    else:
                        candidate[name] = value
            value = agg.get("ratingValue")
            if isinstance(value, str):
                if value.strip():
                    candidate["rating_value"] = value
            elif ((type(value) is int and -10**12 <= value <= 10**12)
                  or (type(value) is float and math.isfinite(value))):
                candidate["rating_value"] = value
            elif value is not None:
                issue = "invalid rating value for the queried number"
            for key, value in candidate.items():
                if key in out and out[key] != value:
                    issue = "conflicting rating metadata for the queried number"
                else:
                    out[key] = value
    return out, issue


@dataclass
class EvidencePage:
    html: str = ""
    ratings: dict = field(default_factory=dict)
    error: str | None = None


def evidence_page(html: str, number: str, region: str | None, url: str) -> EvidencePage:
    """Keep a numbered content region and independently bound JSON-LD ratings."""
    try:
        page = _Page(html)
    except (ValueError, RecursionError):
        return EvidencePage(error="reputation page could not be safely parsed")
    headings = [n for n in page.nodes if n.tag == "h1" and _visible(n)]
    identities = set().union(*(_numbers(n.text(), region) for n in headings))
    if identities and identities != {number}:
        return EvidencePage(error="page heading identifies a different phone number or several numbers")
    _clean(page.root, number, region)
    ratings, issue = _ratings(page, number, region, url)
    if not identities:
        return EvidencePage(ratings=ratings, error=issue or (None if ratings else "page does not identify the queried phone number"))
    heading = next(n for n in headings if _numbers(n.text(), region) == {number})
    scope = heading.parent
    parent = scope
    while parent:
        if parent.tag in ("main", "article", "section"):
            scope = parent
            break
        parent = parent.parent
    if _clean(scope, number, region) - {number}:
        return EvidencePage(ratings=ratings, error="page mixes several phone numbers without separate content regions")
    return EvidencePage(html=scope.render(), ratings=ratings, error=issue)
