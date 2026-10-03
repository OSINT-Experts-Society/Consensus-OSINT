"""Query-bound Faceit player evidence."""

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
    if not isinstance(data, dict) or has_service_error(data) or data.get("result") != "OK":
        return Result.error("No successful Faceit response")
    payload = data.get("payload")
    if not isinstance(payload, dict) or has_service_error(payload):
        return Result.error("No coherent Faceit player payload")
    nickname = payload.get("nickname")
    if not isinstance(nickname, str) or nickname.casefold() != user.casefold():
        return Result.error("Response does not identify the requested Faceit player")
    extra, media = {"nickname": nickname}, {}
    for source, target in (("id", "user_id"), ("country", "country"), ("created_at", "created_at")):
        if value := _text(payload.get(source)):
            extra[target] = value.upper() if source == "country" else value
    if type(payload.get("verified")) is bool:
        extra["verified"] = payload["verified"]
    platforms = payload.get("platforms")
    steam = platforms.get("steam") if isinstance(platforms, dict) else None
    if isinstance(steam, dict) and (value := _text(steam.get("id64"))):
        extra["steam_id64"] = value
    streaming = payload.get("streaming")
    if isinstance(streaming, dict) and (value := _text(streaming.get("twitch_id"))):
        extra["twitch_id"] = value
    for source, target in (("avatar", "avatar"), ("cover_image_url", "banner")):
        if value := _url(payload.get(source)):
            media[target] = value
    return Result.taken(extra=extra, media=media)
