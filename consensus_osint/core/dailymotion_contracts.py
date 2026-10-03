"""Dailymotion legacy user identity and typed optional fields."""

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
    if not isinstance(data, dict) or has_service_error(data) or not _text(data.get("id")):
        return Result.error("No successful typed Dailymotion user")
    username = data.get("username")
    if user != data["id"] and not (isinstance(username, str) and username.casefold() == user.casefold()):
        return Result.error("Dailymotion identifiers do not match the request")
    extra, media = {"id": data["id"]}, {}
    for key in ("username", "screenname", "description", "country"):
        if value := _text(data.get(key)):
            extra[key] = value
    for source, target in (("followers_total", "followers"), ("following_total", "following"), ("videos_total", "videos"), ("created_time", "created_time")):
        if type(data.get(source)) is int and data[source] >= 0:
            extra[target] = data[source]
    if type(data.get("verified")) is bool:
        extra["verified_partner"] = data["verified"]
    for source, target in (("avatar_720_url", "avatar"), ("cover_250_url", "cover")):
        if value := _url(data.get(source)):
            media[target] = value
    return Result.taken(extra=extra, media=media)
