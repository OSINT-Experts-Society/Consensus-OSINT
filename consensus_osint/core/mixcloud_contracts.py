"""Mixcloud user responses bound to their username and documented object key."""

import json
from urllib.parse import quote

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
        return Result.error("No successful Mixcloud user response")
    username, key = data.get("username"), data.get("key")
    expected = "/" + quote(user, safe="") + "/"
    if (not isinstance(username, str) or username.casefold() != user.casefold()
            or not isinstance(key, str) or key.casefold() not in {expected.casefold(), ("/" + user + "/").casefold()}):
        return Result.error("Mixcloud user and object key do not match the requested profile")
    if "url" in data:
        url = data["url"]
        allowed = {scheme + "www.mixcloud.com" + path for scheme in ("https://", "http://") for path in (expected, "/" + user + "/")}
        if not isinstance(url, str) or url.casefold() not in {x.casefold() for x in allowed}:
            return Result.error("Conflicting Mixcloud profile URL")
    extra, media = {"username": username}, {}
    if name := _text(data.get("name")):
        extra["name"] = name
    for source, target in (("follower_count", "followers"), ("following_count", "following")):
        if type(data.get(source)) is int and data[source] >= 0:
            extra[target] = data[source]
    pictures = data.get("pictures")
    if isinstance(pictures, dict):
        for size in ("large", "thumbnail", "small"):
            if value := _url(pictures.get(size)):
                media["avatar"] = value
                break
    return Result.taken(extra=extra, media=media)
