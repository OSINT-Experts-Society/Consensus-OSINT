"""Repair incomplete extraction in four retained user-scanner translations.

Parser behaviour is adapted from the corresponding modules already vendored in
vendor/user_scanner/user_scan (Copyright (c) 2025 Kaif); their MIT licence remains
in vendor/user_scanner/LICENSE.
Exact extraction fingerprints limit these repairs to the affected definitions.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

_LEGACY = {
    "us-user-dev-packagist": "d0631a4daa147496ad1915d0d13cfeb5a39300f57b4d8b46ae04eb0871d78268",
    "us-user-donation-buymeacoffee": "cb458d62d19971c56018849f112abf86c699368a2bc5c6215e2fae5f3f02b5ab",
    "us-user-social-ok": "f218b47c450b80ffae75760cb0869e11f9f37e9cf25fbf57e353eeecb6f3d377",
    "us-user-shopping-andelemandele": "565757d2d797ce0b0e4cafa48999eea0a5c10fb6b0bdf255044d0f4583aed375",
}


class _Markup(HTMLParser):
    def __init__(self, document):
        super().__init__(convert_charrefs=True)
        self.meta = {}
        self.title = ""
        self.packages = set()
        self.products = []
        self.verified = False
        self._hidden = []
        self._structure_limited = False
        self._title = False
        self.feed(document)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        hidden = (bool(self._hidden and self._hidden[-1][1]) or "hidden" in attrs or "inert" in attrs
                  or (attrs.get("aria-hidden") or "").lower() == "true"
                  or bool(re.search(r"(?:display\s*:\s*none|visibility\s*:\s*hidden)", attrs.get("style") or "", re.I)))
        if tag not in ("area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"):
            if len(self._hidden) < 1000:
                self._hidden.append((tag, hidden))
            else:
                self._structure_limited = True
                self.verified = False
        if "verified-badge" in (attrs.get("class") or "").split() and not hidden and not self._structure_limited:
            self.verified = True
        if tag == "meta":
            name = (attrs.get("property") or attrs.get("name") or "").lower()
            content = (attrs.get("content") or "").strip()
            if name and content:
                self.meta.setdefault(name, content)
        elif tag == "title":
            self._title = True
        elif tag == "a":
            target = attrs.get("href") or ""
            try:
                parts = urlsplit(target)
                host = parts.hostname
            except ValueError:
                return
            if parts.scheme in ("", "https", "http") and host in (None, "packagist.org", "www.packagist.org"):
                package = re.fullmatch(r"/packages/([a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*)/?", unquote(parts.path))
                if package:
                    self.packages.add(package.group(1))
            if ("product-card__link" in (attrs.get("class") or "").split() and not parts.scheme and not parts.netloc
                    and re.fullmatch(r"/perle/[^?#]+/", parts.path)):
                self.products.append(parts.path)

    def handle_endtag(self, tag):
        for index in range(len(self._hidden) - 1, -1, -1):
            if self._hidden[index][0] == tag:
                del self._hidden[index:]
                break
        if tag == "title":
            self._title = False

    def handle_data(self, value):
        if self._title:
            self.title += value


def _selected(entry):
    source = entry.get("replaces")
    fingerprint = _LEGACY.get(source)
    if not fingerprint or entry.get("source") != "user-scanner":
        return None
    current = hashlib.sha256(json.dumps(entry.get("extract", []), sort_keys=True,
                                       separators=(",", ":")).encode()).hexdigest()
    return source if current == fingerprint else None


def _capture(pattern, document):
    from .rules import _search

    match = _search(pattern, document, re.I | re.S)
    return html.unescape(match.group(1)).strip() if match else None


def _text(markup):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", markup))).strip()


def _profile(document):
    from .rules import _search

    match = _search(r'<article class="user-profile\b.*?</article>', document, re.S)
    if not match:
        return {}
    card = match.group(0)
    fields = {}
    identity = _capture(r'data-user_id="([0-9]+)"', card)
    if identity is not None:
        try:
            fields["id"] = int(identity)
        except ValueError:
            pass
    if _Markup(card).verified:
        fields["verified"] = True
    for key, pattern in (
        ("name", r"<h1>\s*(.*?)\s*(?:<span|<div|</h1>)"),
        ("bio", r'<p class="user-profile__about hidden-xs">(.*?)</p>'),
    ):
        value = _capture(pattern, card)
        if value:
            fields[key] = _text(value)
    stats = [_text(cell) for cell in re.findall(r"<td>(.*?)</td>", card, re.S)]
    if stats and (value := stats[0].removeprefix("Andelē jau").strip()):
        fields["member_since"] = value
    if len(stats) > 1 and (value := stats[1].removeprefix("Tiešsaistē").strip()):
        fields["last_online"] = value
    if len(stats) > 2 and (items := re.search(r"[0-9]+", stats[2])):
        try:
            fields["items"] = int(items.group(0))
        except ValueError:
            pass
    avatar = _capture(r"background-image:url\('([^']+)'\)", card)
    if avatar:
        fields["media"] = {"avatar": avatar}
    return fields


def extract_legacy(entry, document, fields):
    """Recover fields from the response already fetched; never starts a request."""
    source = _selected(entry)
    if source is None:
        return fields
    fields = dict(fields)
    if source == "us-user-dev-packagist":
        markup = _Markup(document)
        fields.pop("name", None)
        if markup.title.strip():
            fields["name"] = markup.title.replace("- Packagist", "").strip()
        if markup.packages:
            fields["packages_count"] = len(markup.packages)
    elif source == "us-user-donation-buymeacoffee":
        markup = _Markup(document)
        for key, value in (
            ("name", markup.meta.get("og:title") or re.sub(r"\s*-\s*Buymeacoffee$", "", markup.title, flags=re.I).strip()),
            ("bio", markup.meta.get("description") or markup.meta.get("og:description")),
        ):
            fields.pop(key, None)
            if value:
                fields[key] = value
        avatar = markup.meta.get("og:image")
        fields.pop("media", None)
        if avatar:
            fields["media"] = {"avatar": avatar}
    elif source == "us-user-social-ok":
        if not fields.get("ok_id") and (identity := _capture(r"friendId=([0-9]+)", document)):
            fields["ok_id"] = identity
    elif source == "us-user-shopping-andelemandele":
        fields.update(_profile(document))
    return fields


def _iso(value):
    if type(value) is not int:
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _product_fields(document, profile_id):
    raw = _capture(r'data-component="UserInfoCard"[^>]+data-props="([^"]+)"', document)
    if raw is None:
        return {}
    try:
        props = json.loads(raw)
    except (ValueError, RecursionError):
        return {}
    user = props.get("user") if isinstance(props, dict) else None
    if not isinstance(user, dict) or type(user.get("id")) is not int or user["id"] != profile_id:
        return {}
    keys = ("id", "display_name", "first_name", "last_name", "region", "status", "rating", "rating_count",
            "product_count", "follower_count", "following", "blocked", "verification_level", "about", "flags")
    fields = {key: user[key] for key in keys if user.get(key) not in (None, "", [], {})}
    if isinstance(user.get("link"), str) and user["link"]:
        fields["profile_url"] = user["link"]
    for key in ("joined", "last_seen"):
        value = _iso(user.get(key))
        if value is not None:
            fields[key] = value
    for key in ("image_large", "image", "image_small", "image_xsmall"):
        avatar = user.get(key)
        if not isinstance(avatar, str) or not avatar or key == "image_large" and re.search(r"/(?:x?small|medium)/", avatar):
            continue
        fields["media"] = {"avatar": html.unescape(avatar)}
        break
    return fields


async def supplement_legacy(entry, document, fields, http):
    """One optional, read-only product lookup through the caller's HTTP route.

    Keep the profile details on failure. Product fields belong to the profile
    only when their typed numeric user ID matches the ID in the profile card.
    """
    if _selected(entry) != "us-user-shopping-andelemandele" or type(fields.get("id")) is not int:
        return fields
    products = _Markup(document).products
    if not products:
        return fields
    path = products[0]
    from .rules import _send

    ok, status, response, _ = await _send(http, "GET", "https://www.andelemandele.lv" + path,
                                         {"User-Agent": "Mozilla/5.0"}, None, None, True)
    if ok and status == 200:
        return {**fields, **_product_fields(response, fields["id"])}
    return fields
