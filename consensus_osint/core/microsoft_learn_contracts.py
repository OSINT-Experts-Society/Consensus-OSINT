"""Conservative Microsoft Learn profile identity and metadata contract."""

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
    except (ValueError, TypeError):
        data = None
    if (not isinstance(data, dict) or has_service_error(data) or not _text(data.get("userId"))
            or not isinstance(data.get("userName"), str) or data["userName"].casefold() != user.casefold()):
        return Result.error("Response does not identify the requested Microsoft Learn profile")
    extra = {"username": data["userName"], "user_id": data["userId"]}
    for source, target in (("displayName", "name"), ("createdOn", "created_on")):
        if value := _text(data.get(source)):
            extra[target] = value
    for source, target in (("reputationPoints", "reputation"), ("followerCount", "followers"),
                           ("followingCount", "following"), ("answersAccepted", "answers_accepted")):
        if type(data.get(source)) is int and data[source] >= 0:
            extra[target] = data[source]
    return Result.taken(extra=extra)
