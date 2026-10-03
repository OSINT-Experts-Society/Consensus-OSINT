"""Active Nexus Mods profile evidence and conservatively bound enrichment."""

import html
import json
import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.nextjs import iter_next_app_flight_chunks
from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _enrichment(scripts, user):
    candidates = []
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    for script in scripts:
        for chunk in iter_next_app_flight_chunks(script):
            if "UserByName" not in chunk:
                continue
            for match in re.finditer(r'"data"\s*:\s*', chunk):
                try:
                    data, _ = decoder.raw_decode(chunk[match.end():])
                except ValueError:
                    continue
                if not isinstance(data, dict) or has_service_error(data):
                    continue
                names = [data[key] for key in ("name", "username") if key in data]
                if not names or any(not isinstance(name, str) or name.casefold() != user.casefold() for name in names):
                    continue
                member = data.get("memberId")
                if type(member) is not int or member <= 0:
                    continue
                candidates.append(data)
    if len(candidates) != 1:
        return {}
    data = candidates[0]
    extra = {"user_id": data["memberId"]}
    for source, target in (("country", "country"), ("about", "about"), ("paypal", "paypal_email")):
        if value := _text(data.get(source)):
            extra[target] = html.unescape(value)
    if type(data.get("posts")) is int and data["posts"] >= 0:
        extra["posts"] = data["posts"]
    for source, target in (("recognizedAuthor", "recognized_author"), ("donationsEnabled", "donations_enabled")):
        if type(data.get(source)) is bool:
            extra[target] = data[source]
    roles = data.get("membershipRoles")
    if isinstance(roles, list) and roles and all(isinstance(role, str) for role in roles):
        extra["membership_roles"] = ", ".join(roles)
    return extra


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["style", "template"]):
        node.decompose()
    scripts = [node.get_text() for node in page.select("script:not([src])")]
    for node in page("script"):
        node.decompose()
    expected = "https://www.nexusmods.com/profile/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    headings = page.select("h1.text-heading-sm")
    if (not urls or any(value.rstrip("/").casefold() != expected.casefold() for value in urls)
            or len(headings) != 1 or headings[0].get_text(" ", strip=True).casefold() != user.casefold()):
        return Result.error("No unambiguous named Nexus Mods profile")
    title = page.title.get_text(" ", strip=True) if page.title else ""
    if re.search(r"not found|access denied|unavailable", title, re.I):
        return Result.error("Profile page reports missing or unavailable content")
    extra, media = {"username": user}, {}
    images = [node.get("content", "") for node in page.select('meta[property="og:image"]')]
    if len(images) == 1 and (value := _url(images[0])):
        media["avatar"] = value
    for target, marker in (("unique_downloads", "unique-download-count"), ("endorsements_given", "endorsements-given"), ("profile_views", "profile-views"), ("kudos", "kudos")):
        nodes = page.select(f'[data-e2eid="{marker}"]')
        if len(nodes) == 1 and (value := nodes[0].get_text(" ", strip=True)):
            extra[target] = value
    for target, marker in (("last_active", "last-active-date"), ("joined", "joined-date")):
        nodes = page.select(f'[data-e2eid="{marker}"][datetime]')
        if len(nodes) == 1 and (value := _text(nodes[0].get("datetime"))):
            extra[target] = value
    extra.update(_enrichment(scripts, user))
    return Result.taken(extra=extra, media=media)
