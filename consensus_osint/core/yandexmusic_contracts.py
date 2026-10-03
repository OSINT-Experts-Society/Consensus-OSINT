"""Conservative Yandex Music library-owner evidence; live schema unverified."""

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
        return Result.error("No successful Yandex Music library response")
    owner = data.get("owner")
    if not isinstance(owner, dict) or has_service_error(owner):
        return Result.error("No coherent library owner")
    uid = owner.get("uid")
    if not (_text(uid) or (type(uid) is int and uid > 0)):
        return Result.error("No typed Yandex owner UID")
    login = owner.get("login")
    if str(uid) != user and not (isinstance(login, str) and login.casefold() == user.casefold()):
        return Result.error("Owner UID/login does not match query; legacy schema unverified")
    extra = {"yandex_uid": str(uid)}
    if name := _text(owner.get("name")):
        extra["fullname"] = name
    for source, target in (("verified", "is_verified"), ("hasTracks", "has_tracks")):
        if type(data.get(source)) is bool:
            extra[target] = data[source]
    counts = data.get("counts")
    if isinstance(counts, dict) and not has_service_error(counts):
        for source, target in (("likedAlbums", "liked_albums"), ("likedArtists", "liked_artists")):
            if type(counts.get(source)) is int and counts[source] >= 0:
                extra[target] = counts[source]
    return Result.taken(extra=extra)
