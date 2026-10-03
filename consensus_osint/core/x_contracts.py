"""Separate third-party X profile evidence from username availability."""
import json
import re

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def valid_user(user):
    return isinstance(user, str) and re.fullmatch(r"[A-Za-z0-9_]{1,15}", user) is not None


def _body(response):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        raise ValueError(reason)
    data = json.loads(response.text, object_pairs_hook=_unique_object)
    if not isinstance(data, dict) or has_service_error(data):
        raise ValueError("No successful X response object")
    return data


def profile(response, user):
    try:
        data = _body(response)
    except (TypeError, ValueError):
        return Result.error("No successful VXTwitter profile response")
    name = data.get("screen_name")
    if (not isinstance(name, str) or name.casefold() != user.casefold()
            or type(data.get("id")) is not int or data["id"] <= 0):
        return Result.error("VXTwitter profile identity does not match")
    extra = {"username": name, "user_id": data["id"], "profile_confirmed": True,
             "profile_source": "VXTwitter", "scope": "Third-party profile evidence; not proof of current X access or ownership"}
    for key, target in (("name", "name"), ("description", "bio"), ("location", "location"), ("created_at", "created_at")):
        if value := _text(data.get(key)):
            extra[target] = value
    for key, target in (("followers_count", "followers"), ("following_count", "following"), ("tweet_count", "tweets"), ("fetched_on", "fetched_on")):
        if type(data.get(key)) is int and data[key] >= 0:
            extra[target] = data[key]
    if type(data.get("protected")) is bool:
        extra["protected"] = data["protected"]
    media = {}
    if avatar := _url(data.get("profile_image_url")):
        media["avatar"] = avatar
    return Result.taken(extra=extra, media=media)


def availability(response, user):
    if not valid_user(user):
        return Result.error("Invalid X username")
    try:
        data = _body(response)
    except (TypeError, ValueError):
        return Result.error("No successful X availability response")
    if "username" in data and (not isinstance(data["username"], str) or data["username"].casefold() != user.casefold()):
        return Result.error("X availability response identifies another username")
    available, reason = data.get("valid"), data.get("reason")
    extra = {"scope": "Username availability; not proof of a current X profile or ownership"}
    if available is True and reason in (None, "available"):
        return Result.available(extra={**extra, "available": True})
    if available is False and reason == "taken":
        return Result.taken(extra={**extra, "available": False})
    return Result.error("No consistent X username availability result")
