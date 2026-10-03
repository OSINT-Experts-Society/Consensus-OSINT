"""Query-bound Kick channel responses and typed profile metadata."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _count(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20:
        return int(value)
    return None


def _categories(value):
    if not isinstance(value, list):
        return None
    names = [name for item in value if isinstance(item, dict) and (name := _text(item.get("name")))]
    return ", ".join(names) or None


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 404))
    if issue is not None:
        return Result.error(reason)
    try:
        channel = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        channel = None
    if response.status_code == 404:
        if channel == {"message": "Channel not found."}:
            return Result.available()
        return Result.error("No unambiguous channel absence response")
    if not isinstance(channel, dict) or has_service_error(channel):
        return Result.error("No coherent channel response")
    slug = channel.get("slug")
    if (not isinstance(slug, str) or slug.casefold() != user.casefold()
            or channel.get("message") == "Channel not found."):
        return Result.error("Channel response does not identify the requested handle")
    account = _mapping(channel.get("user"))
    stream = _mapping(channel.get("livestream"))
    extra, media = {"username": slug}, {}
    for source, target in (("username", "display_name"), ("bio", "bio"), ("twitter", "twitter"), ("instagram", "instagram"), ("youtube", "youtube"), ("tiktok", "tiktok"), ("facebook", "facebook"), ("discord", "discord")):
        if value := _text(account.get(source)):
            extra[target] = value
    for obj, source, target in ((account, "id", "user_id"), (channel, "id", "channel_id"), (channel, "followers_count", "followers"), (stream, "viewer_count", "stream_viewers")):
        value = _count(obj.get(source))
        if value is not None:
            extra[target] = value
    for obj, source, target in ((channel, "verified", "verified"), (channel, "is_banned", "is_banned"), (channel, "is_affiliate", "is_affiliate"), (channel, "subscription_enabled", "subscriptions_enabled"), (channel, "vod_enabled", "vod_enabled"), (stream, "is_live", "is_live"), (stream, "is_mature", "stream_is_mature")):
        if type(obj.get(source)) is bool:
            extra[target] = obj[source]
    for source, target in (("session_title", "stream_title"), ("start_time", "stream_started_at"), ("language", "stream_language")):
        if value := _text(stream.get(source)):
            extra[target] = value
    for obj, source, target in ((channel, "recent_categories", "recent_categories"), (stream, "categories", "stream_category")):
        if value := _categories(obj.get(source)):
            extra[target] = value
    candidates = {"avatar": account.get("profile_pic"), "banner": _mapping(channel.get("banner_image")).get("url"), "offline_banner": _mapping(channel.get("offline_banner_image")).get("src"), "stream_thumbnail": _mapping(stream.get("thumbnail")).get("url")}
    for target, raw in candidates.items():
        if value := _url(raw):
            media[target] = value
    return Result.taken(extra=extra, media=media)
