"""Beacons structured profile evidence shared by native and catalogue checks."""

import json

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["template", "style"]):
        node.decompose()
    profiles = []
    for node in page.select('script[type="application/ld+json"]'):
        if node.has_attr("src"):
            continue
        try:
            data = json.loads(node.get_text(), object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return Result.error("Invalid structured profile data")
        if isinstance(data, dict) and data.get("@type") == "ProfilePage":
            profiles.append(data)
    if len(profiles) != 1:
        return Result.error("No unique Beacons profile")
    profile = profiles[0]
    person = profile.get("mainEntity")
    if (has_service_error(profile) or not isinstance(person, dict) or has_service_error(person)
            or not isinstance(person.get("identifier"), str)
            or person["identifier"].casefold() != user.casefold()):
        return Result.error("No coherent profile matching the requested username")
    extra, media = {"username": person["identifier"]}, {}
    if value := _text(profile.get("name")) or _text(person.get("name")):
        extra["name"] = value
    if value := _text(profile.get("description")):
        extra["description"] = value
    if value := _url(profile.get("image")) or _url(person.get("image")):
        media["avatar"] = value
    if value := _url(profile.get("significantLink")):
        extra["featured_link"] = value
    links = person.get("sameAs")
    if isinstance(links, list):
        safe = [value for link in links if (value := _url(link))]
        if safe:
            extra["social_links"] = safe
    return Result.taken(extra=extra, media=media)
