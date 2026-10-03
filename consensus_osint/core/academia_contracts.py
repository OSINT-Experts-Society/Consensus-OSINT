"""Academia independent-researcher profile identity and optional metadata."""

import html
import json
import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text as typed_text
from .named_user_contracts import _url
from .provider_contracts import has_service_error


def result(response, user, *, base_url="https://independent.academia.edu"):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["template", "style"]):
        node.decompose()
    profiles = []
    for node in page.select('script[type="application/ld+json"]:not([src])'):
        try:
            data = json.loads(node.get_text(), object_pairs_hook=_unique_object)
        except ValueError:
            return Result.error("Invalid structured profile JSON")
        if isinstance(data, dict) and data.get("@type") == "ProfilePage":
            profiles.append(data)
    if len(profiles) != 1:
        return Result.error("No unique structured profile")
    profile = profiles[0]
    person = profile.get("mainEntity")
    expected = base_url + "/" + quote(user, safe="")
    if (has_service_error(profile) or not isinstance(person, dict) or has_service_error(person)
            or not isinstance(person.get("url"), str) or person["url"].rstrip("/").casefold() != expected.casefold()):
        return Result.error("Profile does not identify the requested Academia profile URL")
    scope = "Academia independent.academia.edu namespace only; institution profiles are not covered" if base_url == "https://independent.academia.edu" else "Academia root-host profile URL only; institution and independent-host profiles are not covered"
    extra = {"username": user, "scope": scope}
    media = {}
    if value := typed_text(person.get("name")):
        extra["name"] = value
    if (value := _url(person.get("image"))) and "no_pic" not in value:
        media["avatar"] = value
    for source, target in (("dateCreated", "joined"), ("dateModified", "updated")):
        if value := typed_text(profile.get(source)):
            extra[target] = value[:10]
    if value := typed_text(profile.get("description")):
        extra["bio"] = value
    links = person.get("sameAs") or profile.get("sameAs")
    if isinstance(links, list):
        safe = [url for raw in links if (url := _url(raw))]
        if safe:
            extra["links"] = ", ".join(safe)
    # Keep only JSON pill scripts for the existing interest metadata parser.
    for node in list(page("script")):
        if node.get("data-component-name") != "Pill":
            node.decompose()
    document = str(page)
    affiliations = page.select(".affiliations-container")
    if len(affiliations) == 1:
        extra["affiliation"] = affiliations[0].get_text(" ", strip=True)
    ids = {node.get("data-follow-user-id") for node in page.select("[data-follow-user-id]")}
    if len(ids) == 1:
        uid = ids.pop()
        if isinstance(uid, str) and re.fullmatch(r"[0-9]{1,25}", uid):
            extra["user_id"] = uid
            extra.update(_extract_interests(document, uid))
    for node in page("script"):
        node.decompose()
    document = str(page)
    extra.update(_extract_stats(document))
    extra.update(_extract_bio_details(document))
    return Result.taken(extra=extra, media=media)


def _extract_interests(html_text: str, user_id: str) -> dict:
    interests = {}

    total = re.search(
        rf'data-has-card-for-ri-list="{user_id}"[^>]*>View All \((\d+)\)', html_text
    )
    if total:
        interests["interests_count"] = total.group(1)

    # The interest pills render as sibling React payloads; keying the enclosing
    # anchor on the owner's id keeps a recommendation carousel out of the list.
    labels: list[str] = []
    for anchor in re.findall(
        rf'data-has-card-for-ri-list="{user_id}"(.*?)</a>', html_text, re.DOTALL
    ):
        pill = re.search(r'data-component-name="Pill"[^>]*>(\{.*?\})</script>', anchor, re.DOTALL)
        if not pill:
            continue
        try:
            children = json.loads(pill.group(1), object_pairs_hook=_unique_object).get("children") or []
        except (ValueError, AttributeError):
            continue
        if isinstance(children, list):
            labels.extend(child for child in children if isinstance(child, str))

    if labels:
        interests["interests"] = ", ".join(labels)

    return interests


def _extract_stats(html_text: str) -> dict:
    region = re.search(r'class="user-stats-container"(.*?)<aside', html_text, re.DOTALL)
    if not region:
        return {}

    stats = {}
    for label, value in re.findall(
        r'<p class="label">(.*?)</p>\s*<p class="data">(.*?)</p>', region.group(1), re.DOTALL
    ):
        stats["stat_" + _text(label)] = _text(value)
    return stats


def _extract_bio_details(html_text: str) -> dict:
    bio = re.search(r'class="profile-bio[^"]*"[^>]*>(.*?)</div>', html_text, re.DOTALL)
    if not bio:
        return {}

    return {
        "detail_" + _text(label): _text(value)
        for label, value in re.findall(
            r'<span class="u-fw700">(.*?):.*?</span>(.*?)<br\s*/?>', bio.group(1), re.DOTALL
        )
    }


def _text(html_fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", html_fragment))).strip()
