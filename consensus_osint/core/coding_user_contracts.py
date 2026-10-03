"""Bound Codeforces and LeetCode responses; generic failures are inconclusive."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def result(response, site, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (ValueError, TypeError):
        data = None
    if not isinstance(data, dict):
        return Result.error("Invalid user response")
    if site == "leetcode":
        envelope = data.get("data")
        errors = data.get("errors")
        remainder = {k: v for k, v in data.items() if k != "errors"}
        if (
            isinstance(envelope, dict)
            and "matchedUser" in envelope
            and envelope["matchedUser"] is None
            and isinstance(errors, list)
            and len(errors) == 1
            and isinstance(errors[0], dict)
            and errors[0].get("message") in ("That user does not exist", "That user does not exist.")
            and ("path" not in errors[0] or errors[0]["path"] == ["matchedUser"])
            and not has_service_error(remainder)
            and not has_service_error(envelope)
        ):
            return Result.available()
    if has_service_error(data):
        return Result.error("API reports an error")
    extra, media = {}, {}
    if site == "codeforces":
        rows = data.get("result")
        if data.get("status") != "OK" or not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            return Result.error("No single Codeforces user returned")
        record = rows[0]
        name = record.get("handle")
    else:
        envelope = data.get("data")
        if not isinstance(envelope, dict) or has_service_error(envelope):
            return Result.error("No profile envelope")
        record = envelope.get("matchedUser")
        name = record.get("username") if isinstance(record, dict) else None
    if (
        not isinstance(record, dict)
        or has_service_error(record)
        or not isinstance(name, str)
        or name.casefold() != user.casefold()
    ):
        return Result.error("User identity does not match query")
    extra["username"] = name
    if site == "codeforces":
        for key in ("firstName", "lastName", "country", "city", "organization", "rank", "maxRank"):
            if value := _text(record.get(key)):
                extra[key] = value
        for key in ("rating", "maxRating", "friendOfCount"):
            if type(record.get(key)) is int and (key != "friendOfCount" or record[key] >= 0):
                extra[key] = record[key]
    else:
        profile = record.get("profile")
        if isinstance(profile, dict):
            for source, target in (
                ("realName", "fullname"),
                ("aboutMe", "bio"),
                ("countryName", "country"),
                ("company", "company"),
                ("school", "school"),
            ):
                if value := _text(profile.get(source)):
                    extra[target] = value
            if type(profile.get("ranking")) is int and profile["ranking"] >= 0:
                extra["ranking"] = profile["ranking"]
            if value := _url(profile.get("userAvatar")):
                media["image"] = value
    return Result.taken(extra=extra, media=media)
