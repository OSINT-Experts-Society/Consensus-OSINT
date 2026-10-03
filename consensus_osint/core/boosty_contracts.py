"""Boosty blog identity and independently typed optional metadata."""

import json

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
        return Result.error("No coherent Boosty blog response")
    blog = data.get("blogUrl")
    owner = data.get("owner")
    if not isinstance(blog, str) or blog.casefold() != user.casefold():
        return Result.error("Blog does not identify the requested handle")
    if not isinstance(owner, dict) or has_service_error(owner):
        return Result.error("No coherent blog owner")
    identity = owner.get("id")
    if not (_text(identity) or (type(identity) is int and identity > 0)):
        return Result.error("No blog owner ID")
    extra, media = {"username": blog, "owner_id": identity}, {}
    if title := _text(data.get("title")):
        extra["display_name"] = title
    if name := _text(owner.get("name")):
        if name != extra.get("display_name"):
            extra["owner_name"] = name
    if avatar := _url(owner.get("avatarUrl")):
        media["avatar"] = avatar
    counts = data.get("count")
    if isinstance(counts, dict):
        for key in ("subscribers", "posts"):
            if type(counts.get(key)) is int and counts[key] >= 0:
                extra[key] = counts[key]
    links = data.get("socialLinks")
    if isinstance(links, list):
        safe = [url for link in links if isinstance(link, dict) and (url := _url(link.get("url")))]
        if safe:
            extra["links"] = safe
    return Result.taken(extra=extra, media=media)
