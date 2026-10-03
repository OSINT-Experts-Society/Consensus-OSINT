"""Bound public Cropty and Destream user responses."""

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
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No coherent user response")
    record = data.get("data") if site == "cropty" else data
    key = "nickname" if site == "cropty" else "userName"
    if (not isinstance(record, dict) or has_service_error(record) or not isinstance(record.get(key), str)
            or record[key].casefold() != user.casefold()):
        return Result.error("Returned user does not match requested identifier")
    extra, media = {}, {}
    if site == "cropty":
        extra["nickname"] = record[key]
        if value := _text(record.get("name")):
            extra["name"] = value
        if value := _url(record.get("ref_link")):
            extra["referral_link"] = value
        if (value := _url(record.get("image"))) and "defaults" not in value:
            media["avatar"] = value
    else:
        extra["username"] = record[key]
        for source, target in (("liveStream", "live_stream"), ("channel", "channel")):
            if value := _text(record.get(source)):
                extra[target] = value
        if value := _url(record.get("logoImageUrl")):
            media["avatar"] = value
    return Result.taken(extra=extra, media=media)
