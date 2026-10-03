"""Warframe Market public user evidence bound to the documented route slug."""

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
        body = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        body = None
    if not isinstance(body, dict) or has_service_error(body):
        return Result.error("No coherent Warframe Market response")
    data = body.get("data")
    if (not isinstance(data, dict) or has_service_error(data)
            or not _text(data.get("id")) or not isinstance(data.get("slug"), str)
            or data["slug"].casefold() != user.casefold()):
        return Result.error("Response does not identify the requested Warframe Market profile")
    extra = {"id": data["id"], "username": data["slug"]}
    for key in ("role", "ingameName", "status", "lastSeen", "platform"):
        if value := _text(data.get(key)):
            extra[key] = value
    for key in ("reputation", "masteryRank"):
        if type(data.get(key)) is int:
            extra[key] = data[key]
    return Result.taken(extra=extra)
