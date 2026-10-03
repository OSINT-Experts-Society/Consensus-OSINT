"""Conservative Picsart username evidence; endpoint schema remains unverified."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data) or data.get("status") != "success":
        return Result.error("No coherent successful Picsart response")
    identity = data.get("id")
    if (not isinstance(data.get("username"), str) or data["username"].casefold() != user.casefold()
            or not (_text(identity) or (type(identity) is int and identity > 0))):
        return Result.error("No matching Picsart username and ID; endpoint identity schema is unverified")
    extra = {"username": data["username"], "id": identity}
    for key in ("name", "status_message"):
        if value := _text(data.get(key)):
            extra[key] = value
    for source, target in (("followers_count", "followers"), ("following_count", "following"), ("likes_count", "likes"), ("photos_count", "photos")):
        if type(data.get(source)) is int and data[source] >= 0:
            extra[target] = data[source]
    return Result.taken(extra=extra)
