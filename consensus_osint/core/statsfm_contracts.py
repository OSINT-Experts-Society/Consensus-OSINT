"""Stats.fm public user identity and typed optional fields."""

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
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No successful Stats.fm response")
    item = data.get("item")
    if not isinstance(item, dict) or has_service_error(item) or not _text(item.get("id")):
        return Result.error("No typed Stats.fm user")
    custom_id = item.get("customId")
    if user != item["id"] and not (isinstance(custom_id, str) and custom_id.casefold() == user.casefold()):
        return Result.error("Stats.fm user identifiers do not match the request")
    extra = {"id": item["id"]}
    for key in ("customId", "displayName", "createdAt"):
        if value := _text(item.get(key)):
            extra[key] = value
    for key in ("isPlus", "isPro", "quarantined"):
        if type(item.get(key)) is bool:
            extra[key] = item[key]
    return Result.taken(extra=extra)
