"""Bound Unsplash user evidence and independent statistics enrichment."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _body(response):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return None, reason
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return None, "No coherent Unsplash response"
    return data, ""


def result(response, user):
    profile, reason = _body(response)
    if profile is None:
        return Result.error(reason)
    if not isinstance(profile.get("username"), str) or profile["username"].casefold() != user.casefold():
        return Result.error("Profile does not identify the requested Unsplash user")
    extra, media = {"username": profile["username"]}, {}
    for source, target in (("name", "name"), ("id", "id"), ("bio", "bio"), ("location", "location"), ("instagram_username", "instagram"), ("twitter_username", "twitter")):
        if value := _text(profile.get(source)):
            extra[target] = value
    if value := _url(profile.get("portfolio_url")):
        extra["portfolio"] = value
    for source, target in (("numeric_id", "numeric_id"), ("total_photos", "photos"), ("total_illustrations", "illustrations"), ("total_collections", "collections"), ("total_likes", "likes")):
        if type(profile.get(source)) is int and profile[source] >= 0:
            extra[target] = profile[source]
    badge = profile.get("badge")
    if isinstance(badge, dict) and (value := _text(badge.get("title"))):
        extra["badge"] = value
    if type(profile.get("for_hire")) is bool:
        extra["for_hire"] = profile["for_hire"]
    images = profile.get("profile_image")
    if isinstance(images, dict):
        for size in ("large", "medium", "small"):
            if value := _url(images.get(size)):
                media["avatar"] = value
                break
    return Result.taken(extra=extra, media=media)


def downloads(response, user):
    data, _ = _body(response)
    if data is None:
        return None
    if "username" in data and (not isinstance(data["username"], str) or data["username"].casefold() != user.casefold()):
        return None
    counts = data.get("downloads")
    if not isinstance(counts, dict) or has_service_error(counts):
        return None
    total = counts.get("total")
    return total if type(total) is int and total >= 0 else None
