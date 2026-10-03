import hashlib
import html
import json
import re
from collections.abc import Iterator
from urllib.parse import urlsplit

import httpx
from bs4 import BeautifulSoup

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.helpers import get_global_timeout
from consensus_osint.vendor.user_scanner.core.result import Result

PROFILE_HOST = "https://gravatar.com"
DEFAULT_TIMEOUT = 15.0

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# The public JSON APIs omit the profile's "Links" card, its interests and the
# advanced-details panel; only the rendered profile page carries them.
INTERESTS_RE = re.compile(r"<h2[^>]*>\s*Interests\s*</h2>.*?<ul[^>]*>(.*?)</ul>", re.S)
INTEREST_ITEM_RE = re.compile(r"<span>\s*([^<]+?)\s*</span>")
TITLE_RE = re.compile(r'title="([^"]*)"')
ADV_DETAIL_RE = re.compile(r"<span>\s*(Profile|Updated|Created|Languages|Time):\s*([^<]+?)\s*</span>")
# Both JSON APIs list only the providers their schema knows about â€” a YouTube
# connection is absent from each yet rendered on the page, so the card is the
# only complete source. Each entry is anchored on its checkmark's help link and
# the rel="me" of the account anchor rather than on styling hooks.
VERIFIED_MARKER = "support.gravatar.com/profiles/verified-accounts"
VERIFIED_LABEL_RE = re.compile(r">\s*([^<>]{1,60}?)\s*</span>\s*<a[^>]*$", re.S)
ANCHOR_RE = re.compile(r"<a\b[^>]*>", re.S)
REL_ME_RE = re.compile(r'rel="[^"]*\bme\b[^"]*"')
HREF_RE = re.compile(r'href="([^"]+)"')
TIMEZONE_RE = re.compile(r"\(([^)]+)\)")

ADV_DETAIL_KEYS = {
    "Profile": "profile_type",
    "Updated": "last_updated",
    "Created": "created",
    "Languages": "languages",
}


async def validate_gravatar(email: str) -> Result:
    email_clean = email.lower().strip()
    timeout = get_global_timeout() or DEFAULT_TIMEOUT
    # Older profiles are only addressable by the legacy MD5 hash.
    hashes = [
        hashlib.sha256(email_clean.encode("utf-8")).hexdigest(),
        hashlib.md5(email_clean.encode("utf-8")).hexdigest(),
    ]
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for email_hash in hashes:
                response = await client.get(
                    f"https://www.gravatar.com/avatar/{email_hash}?d=404", headers=HEADERS, follow_redirects=False
                )
                issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 404))
                if issue is not None:
                    return Result.error(reason, url=PROFILE_HOST)
                avatar = response.status_code == 200 and _image_body(response)
                if response.status_code == 200 and not avatar:
                    return Result.error("Avatar response lacks a supported image body", url=PROFILE_HOST)
                extra, media, profile = await _collect_profile(client, email_hash, hashes, email_clean)
                if avatar or profile:
                    extra["scope"] = "Public avatar/profile association; not proof of ownership or activity"
                    if avatar:
                        media["avatar"] = f"https://www.gravatar.com/avatar/{email_hash}"
                    return Result.taken(url=extra.get("profile_url", PROFILE_HOST), extra=extra, media=media)
            return Result.error(
                "No public avatar or bound profile found; this does not establish account absence", url=PROFILE_HOST
            )
    except httpx.TimeoutException:
        return Result.error("Connection timed out", url=PROFILE_HOST)
    except Exception as e:
        return Result.error(e, url=PROFILE_HOST)


def _image_body(response) -> bool:
    kind = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    body = response.content
    return (
        kind == "image/png"
        and body.startswith(b"\x89PNG\r\n\x1a\n")
        and len(body) > 24
        or kind == "image/jpeg"
        and body.startswith(b"\xff\xd8\xff")
        and body.endswith(b"\xff\xd9")
        and len(body) > 20
        or kind == "image/gif"
        and body[:6] in (b"GIF87a", b"GIF89a")
        and len(body) > 13
        or kind == "image/webp"
        and body[:4] == b"RIFF"
        and body[8:12] == b"WEBP"
        and len(body) > 20
    )


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _url(value, *, profile=False):
    value = _text(value)
    if not value or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            return None
        if profile and (
            parsed.scheme != "https" or parsed.hostname not in ("gravatar.com", "www.gravatar.com", "en.gravatar.com")
        ):
            return None
        return value
    except ValueError:
        return None


async def _collect_profile(client, email_hash, hashes, email) -> tuple[dict, dict, bool]:
    extra, media = {}, {}
    bound = False
    try:
        response = await client.get(
            f"https://en.gravatar.com/{email_hash}.json", headers=HEADERS, follow_redirects=False
        )
        issue, _ = http_issue(response.status_code, response.headers, response.text)
        if issue is None:
            data = json.loads(response.text, object_pairs_hook=_unique_object)
            entries = data.get("entry") if isinstance(data, dict) and not has_service_error(data) else None
            if isinstance(entries, list) and len(entries) == 1 and isinstance(entries[0], dict):
                entry = entries[0]
                digest = entry.get("hash")
                bound = (
                    isinstance(digest, str)
                    and digest.lower() in hashes
                    and not has_service_error(entry)
                    and all(
                        "email" not in obj
                        or isinstance(obj["email"], str)
                        and obj["email"].casefold() == email.casefold()
                        for obj in (data, entry)
                    )
                )
                if bound:
                    _extract_profile_data(entry, extra, media)
    except Exception:
        pass
    if bound and extra.get("profile_url"):
        try:
            response = await client.get(f"{PROFILE_HOST}/{email_hash}", headers=HEADERS, follow_redirects=False)
            issue, _ = http_issue(response.status_code, response.headers, response.text)
            if issue is None:
                page = BeautifulSoup(response.text, "html.parser")
                for inert in page.select("script,style,template,noscript"):
                    inert.decompose()
                canonical = page.select('link[rel="canonical"]')
                if len(canonical) == 1 and _url(canonical[0].get("href"), profile=True) == extra["profile_url"]:
                    _extract_page_data(str(page), extra)
        except Exception:
            pass
    return extra, media, bound


def _extract_profile_data(entry: dict, extra: dict, media: dict) -> None:
    for source, target in (
        ("preferredUsername", "username"),
        ("displayName", "display_name"),
        ("aboutMe", "bio"),
        ("currentLocation", "location"),
        ("job_title", "job_title"),
        ("jobTitle", "job_title"),
        ("company", "company"),
        ("pronouns", "pronouns"),
        ("pronunciation", "pronunciation"),
    ):
        if value := _text(entry.get(source)):
            extra[target] = value
    if value := _url(entry.get("profileUrl"), profile=True):
        extra["profile_url"] = value
    if value := _url(entry.get("thumbnailUrl")):
        media["thumbnail_url"] = value
    name = entry.get("name")
    if isinstance(name, dict) and (value := _text(name.get("formatted"))):
        extra["full_name"] = value
    for source, target, label, default, is_url in (
        ("photos", "photos", None, None, True),
        ("urls", "websites", None, None, True),
        ("contactInfo", "contact_info", "type", "contact", False),
        ("phoneNumbers", "phone_numbers", "type", "phone", False),
        ("emails", "public_emails", None, None, False),
        ("crypto", "crypto_addresses", "currency", "Wallet", False),
    ):
        rows = entry.get(source)
        values = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            value = (_url if is_url else _text)(row.get("value"))
            if value:
                values.append(f"{_text(row.get(label)) or default}: {value}" if label else value)
        if values:
            (media if source == "photos" else extra)[target] = ", ".join(values)
    accounts = entry.get("accounts")
    values = []
    for account in accounts if isinstance(accounts, list) else []:
        if not isinstance(account, dict):
            continue
        name = _text(account.get("name")) or _text(account.get("shortname")) or "Account"
        url = _url(account.get("url"))
        if url and VERIFIED_MARKER in url:
            url = None
        handle = _text(account.get("display")) or _text(account.get("username"))
        verified = account.get("verified") is True
        value = url or handle
        if value or verified:
            values.append(name + (f": {value}" if value else "") + (" (verified)" if verified else ""))
    if values:
        extra["verified_accounts"] = ", ".join(values)
    background = entry.get("profileBackground")
    if isinstance(background, dict):
        if value := _url(background.get("url")):
            media["background"] = value
        if value := _text(background.get("color")):
            extra["background_color"] = value


def _extract_page_data(page: str, extra: dict) -> None:
    clean = BeautifulSoup(page, "html.parser")
    for inert in clean.select("script,style,template,noscript"):
        inert.decompose()
    page = str(clean)
    _merge_verified_accounts(page, extra)

    links = []
    for title, url in _iter_links(page):
        entry = f"{title}: {url}"
        if entry not in links:
            links.append(entry)
    if links:
        extra["links"] = ", ".join(links)

    interests = INTERESTS_RE.search(page)
    if interests:
        items = [html.unescape(i).strip() for i in INTEREST_ITEM_RE.findall(interests.group(1))]
        items = [i for i in items if i]
        if items:
            extra["interests"] = ", ".join(items)

    for label, value in ADV_DETAIL_RE.findall(page):
        value = html.unescape(value).strip()
        if not value or value == "-":
            continue
        if label == "Time":
            zone = TIMEZONE_RE.search(value)
            # Profiles with no timezone set render as UTC, so a bare "UTC" says
            # nothing about the owner and is dropped.
            if zone and zone.group(1).strip() != "UTC":
                extra["timezone"] = zone.group(1).strip()
            continue
        extra[ADV_DETAIL_KEYS[label]] = value


def _merge_verified_accounts(page: str, extra: dict) -> None:
    existing = [e for e in str(extra.get("verified_accounts", "")).split(", ") if e]
    known_urls = {_normalize_url(e.rsplit(": ", 1)[-1]) for e in existing}
    # The same account can carry different URLs in each source â€” the JSON keeps
    # whatever the owner entered, the page renders a canonical one â€” so the
    # service name is what identifies a duplicate.
    known_services = {e.split(":", 1)[0].removesuffix(" (verified)").strip().lower() for e in existing}
    for label, url in _iter_verified_accounts(page):
        if _normalize_url(url) in known_urls or label.lower() in known_services:
            continue
        known_urls.add(_normalize_url(url))
        known_services.add(label.lower())
        existing.append(f"{label or 'Account'}: {url} (verified)")
    if existing:
        extra["verified_accounts"] = ", ".join(existing)


def _iter_verified_accounts(page: str) -> Iterator[tuple[str, str]]:
    soup = BeautifulSoup(page, "html.parser")
    marker_url = "https://" + VERIFIED_MARKER
    for marker in soup.find_all("a", href=True):
        if marker.get("href", "").rstrip("/") != marker_url:
            continue
        # Bind the marker and account link to the same local card.
        card = marker.find_parent(["li", "article", "div"])
        if card is None or card.find_parent(["template", "noscript"]):
            continue
        links = [a for a in card.select('a[rel~="me"]') if a is not marker and _url(a.get("href"))]
        markers = [a for a in card.find_all("a", href=True) if a.get("href", "").rstrip("/") == marker_url]
        if len(links) != 1 or len(markers) != 1:
            continue
        link = links[0]
        url = link["href"].strip()
        if VERIFIED_MARKER in url:
            continue
        label = link.get_text(" ", strip=True)
        yield label if label != url else "", url


def _iter_links(page: str) -> Iterator[tuple[str, str]]:
    # A personal link carries the owner's own caption; every other rel="me"
    # anchor on the page â€” the icon row and the verified cards â€” repeats its own
    # URL as the title.
    for tag in ANCHOR_RE.finditer(page):
        if not REL_ME_RE.search(tag.group(0)):
            continue
        href = HREF_RE.search(tag.group(0))
        title = TITLE_RE.search(tag.group(0))
        if not href or not title:
            continue
        url = html.unescape(href.group(1)).strip()
        caption = html.unescape(title.group(1)).strip()
        if _url(url) and caption and caption != url:
            yield caption, url


def _normalize_url(value: str) -> str:
    return value.removesuffix(" (verified)").strip().rstrip("/").lower()
