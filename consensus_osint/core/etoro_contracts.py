"""Structured, query-bound eToro user evidence."""

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
    if not isinstance(data, dict) or has_service_error(data) or data.get("ErrorCode") not in (None, "", False):
        return Result.error("No coherent user response")
    names = [data[key] for key in ("username", "userName") if key in data]
    if (type(data.get("gcid")) is not int or data["gcid"] <= 0 or not names
            or any(not isinstance(value, str) or value.casefold() != user.casefold() for value in names)):
        return Result.error("Response does not identify the requested eToro user")
    extra, media = {"username": names[0], "gcid": data["gcid"]}, {}
    parts = [value for key in ("firstName", "lastName") if (value := _text(data.get(key)))]
    if parts:
        extra["name"] = " ".join(parts)
    if value := _text(data.get("aboutMe")) or _text(data.get("aboutMeShort")):
        extra["bio"] = value
    if type(data.get("isVerified")) is bool:
        extra["is_verified"] = data["isVerified"]
    avatars = data.get("avatars")
    if isinstance(avatars, list):
        for avatar in avatars:
            if isinstance(avatar, dict) and (value := _url(avatar.get("url"))):
                media["avatar"] = value
                break
    return Result.taken(extra=extra, media=media)
