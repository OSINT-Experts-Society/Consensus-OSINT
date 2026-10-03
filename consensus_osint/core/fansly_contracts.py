"""Single-name Fansly account evidence and typed optional counters."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text
from .provider_contracts import has_service_error


def valid_user(user):
    return bool(user) and not any(char == "," or ord(char) <= 32 or ord(char) == 127 for char in user)


def result(response, user):
    if not valid_user(user):
        return Result.error("One Fansly username is required")
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data) or data.get("success") is not True:
        return Result.error("No coherent successful Fansly response")
    accounts = data.get("response")
    if accounts == []:
        return Result.available()
    if not isinstance(accounts, list) or len(accounts) != 1:
        return Result.error("No unique account response")
    account = accounts[0]
    if (not isinstance(account, dict) or has_service_error(account)
            or not isinstance(account.get("username"), str) or account["username"].casefold() != user.casefold()
            or not _text(account.get("id"))):
        return Result.error("Response does not identify the requested Fansly username")
    extra = {"username": account["username"], "id": account["id"]}
    if value := _text(account.get("displayName")):
        extra["displayName"] = value
    if type(account.get("followCount")) is int and account["followCount"] >= 0:
        extra["followers"] = account["followCount"]
    stats = account.get("timelineStats")
    if isinstance(stats, dict):
        for source, target in (("imageCount", "images"), ("videoCount", "videos")):
            if type(stats.get(source)) is int and stats[source] >= 0:
                extra[target] = stats[source]
    return Result.taken(extra=extra)
