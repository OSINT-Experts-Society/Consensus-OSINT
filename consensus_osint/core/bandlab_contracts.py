"""BandLab profile identity and independently typed optional metadata."""

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
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No coherent successful BandLab response")
    identity = data.get("id")
    if (not isinstance(data.get("username"), str) or data["username"].casefold() != user.casefold()
            or not (_text(identity) or (type(identity) is int and identity > 0))):
        return Result.error("No matching BandLab username and ID")
    extra = {"username": data["username"], "id": identity}
    for source, target in (("name", "name"), ("about", "bio"), ("place", "location"), ("createdOn", "joined")):
        if value := _text(data.get(source)):
            extra[target] = value
    counters = data.get("counters")
    if isinstance(counters, dict) and not has_service_error(counters):
        for key in ("followers", "following", "plays", "bands"):
            if type(counters.get(key)) is int and counters[key] >= 0:
                extra[key] = counters[key]
    media = {}
    picture = data.get("picture")
    if isinstance(picture, dict) and (value := _url(picture.get("url"))):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
