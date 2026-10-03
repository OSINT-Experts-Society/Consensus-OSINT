"""Conservative legacy Vimeo user API identity and typed metadata."""

import json
from urllib.parse import quote, urlsplit

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No successful Vimeo user response")
    identity = data.get("id")
    if not (_text(identity) or (type(identity) is int and identity > 0)):
        return Result.error("No typed Vimeo user ID")
    profile_url = data.get("profile_url")
    matched = False
    if isinstance(profile_url, str):
        try:
            parsed = urlsplit(profile_url)
            matched = (parsed.scheme in ("http", "https") and parsed.netloc == "vimeo.com"
                       and not parsed.query and not parsed.fragment
                       and parsed.path.rstrip("/").casefold() == ("/" + quote(user, safe="")).casefold())
        except ValueError:
            pass
    id_alias = str(identity).isascii() and str(identity).isdigit() and user.casefold() == "user" + str(identity)
    if not matched and not id_alias:
        return Result.error("No matching Vimeo profile URL or user-ID alias; legacy schema unverified")
    extra = {"id": identity, "username": user}
    for key in ("display_name", "created_on", "location", "bio"):
        if value := _text(data.get(key)):
            extra[key] = value
    for source, target in (("total_videos_uploaded", "videos"), ("total_contacts", "contacts"), ("total_channels", "channels"), ("total_videos_liked", "liked")):
        if type(data.get(source)) is int and data[source] >= 0:
            extra[target] = data[source]
    return Result.taken(extra=extra)


def page_result(response, user):
    """Vimeo profile HTML, independently of the legacy API response schema."""
    from bs4 import BeautifulSoup

    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["template", "style"]):
        node.decompose()
    expected = "https://vimeo.com/" + quote(user, safe="")
    people = []
    for node in page.select('script[type="application/ld+json"]:not([src])'):
        try:
            data = json.loads(node.get_text(), object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict) or has_service_error(item):
                continue
            if item.get("@type") == "Person" and isinstance(item.get("url"), str):
                if item["url"].rstrip("/").casefold() == expected.casefold():
                    people.append(item)
    for node in page("script"):
        node.decompose()
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No matching Vimeo profile URL")
    kinds = [node.get("content", "").casefold() for node in page.select('meta[property="og:type"]')]
    if len(people) > 1 or (kinds and any(kind not in ("profile", "website") for kind in kinds)):
        return Result.error("Conflicting Vimeo profile metadata")
    if kinds != ["profile"] and len(people) != 1:
        return Result.error("No profile-specific Vimeo evidence")
    extra, media = {"username": user}, {}
    if len(people) == 1:
        for source, target in (("name", "display_name"), ("description", "bio")):
            if value := _text(people[0].get(source)):
                extra[target] = value
    images = page.select('meta[property="og:image"]')
    if len(images) == 1 and (value := _url(images[0].get("content"))):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
