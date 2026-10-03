"""Substack public user profile identity, distinct from publication subdomains."""

import json
import re

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
        return Result.error("No coherent Substack profile response")
    handle, identity = data.get("handle"), data.get("id")
    if (not isinstance(handle, str) or handle.casefold() != user.casefold()
            or not (_text(identity) or (type(identity) is int and identity > 0))):
        return Result.error("No matching Substack handle and profile ID")
    extra, media = {"handle": handle, "id": identity}, {}
    for source, target in (("name", "display_name"), ("bio", "bio")):
        if value := _text(data.get(source)):
            extra[target] = value
    if value := _url(data.get("photo_url")):
        media["avatar"] = value
    for source, target in (("subscriberCountNumber", "subscribers"), ("followerCount", "followers")):
        if type(data.get(source)) is int and data[source] >= 0:
            extra[target] = data[source]
    publication = data.get("primaryPublication")
    if isinstance(publication, dict) and not has_service_error(publication):
        if value := _text(publication.get("name")):
            extra["publication_name"] = value
        subdomain = publication.get("subdomain")
        if isinstance(subdomain, str) and re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", subdomain):
            extra["publication_url"] = f"https://{subdomain}.substack.com"
    return Result.taken(extra=extra, media=media)


def publication_result(response, user):
    """Match publication state; this does not establish a same-named user account."""
    from bs4 import BeautifulSoup

    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["template", "style"]):
        node.decompose()
    states = []
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    for node in page.select("script:not([src])"):
        script = node.get_text()
        for match in re.finditer(r"window\._preloads\s*=\s*JSON\.parse\(", script):
            try:
                encoded, end = decoder.raw_decode(script[match.end():].lstrip())
                tail = script[match.end():].lstrip()[end:].lstrip()
                if not isinstance(encoded, str) or not tail.startswith(")"):
                    return Result.error("Invalid publication state assignment")
                states.append(json.loads(encoded, object_pairs_hook=_unique_object))
            except (TypeError, ValueError):
                return Result.error("Invalid publication state JSON")
    if len(states) != 1 or not isinstance(states[0], dict) or has_service_error(states[0]):
        return Result.error("No unique successful publication state")
    publication = states[0].get("pub")
    if not isinstance(publication, dict) or has_service_error(publication):
        return Result.error("No publication in returned page")
    subdomain, identity = publication.get("subdomain"), publication.get("id")
    if (not isinstance(subdomain, str) or subdomain.casefold() != user.casefold()
            or not (_text(identity) or (type(identity) is int and identity > 0))):
        return Result.error("Publication does not match requested subdomain")
    extra = {"publication_subdomain": subdomain, "publication_id": identity,
             "scope": "Substack publication; not a same-named user account"}
    if name := _text(publication.get("name")):
        extra["publication_name"] = name
    return Result.taken(extra=extra)
