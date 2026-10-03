"""Coherent Monkeytype name availability and query-bound public profiles."""

import json
import math
import re
from datetime import datetime, timezone

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _body(response, accepted=(200,)):
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=accepted)
    if issue is not None:
        return None, reason
    try:
        body = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        body = None
    if not isinstance(body, dict):
        return None, "No structured Monkeytype response"
    return body, ""


def availability(response, user):
    body, reason = _body(response, (200, 400, 422))
    if body is None:
        return "unknown", reason
    errors = body.get("validationErrors")
    if response.status_code in (400, 422) and isinstance(errors, list) and errors and all(isinstance(e, str) and e for e in errors):
        return "profile", "Name rejected; inspect public profile independently"
    data = body.get("data")
    if (response.status_code != 200 or has_service_error(body) or errors
            or not isinstance(data, dict) or has_service_error(data) or data.get("validationErrors")):
        return "unknown", "No coherent name availability response"
    if "name" in data and (not isinstance(data["name"], str) or data["name"].casefold() != user.casefold()):
        return "unknown", "Availability response names another user"
    if data.get("available") is True:
        return "available", "Name available for registration"
    if data.get("available") is False:
        return "profile", "Unavailable names require public profile evidence"
    return "unknown", "No typed name availability"


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _number(value):
    return type(value) in (int, float) and 0 <= value <= 1e15 and math.isfinite(value)


def result(response, user):
    body, reason = _body(response)
    if body is None:
        return Result.error(reason)
    data = body.get("data")
    if (has_service_error(body) or body.get("validationErrors") or body.get("message") == "User not found" or not isinstance(data, dict)
            or has_service_error(data) or not isinstance(data.get("name"), str)
            or data["name"].casefold() != user.casefold()):
        return Result.error("Response does not identify the requested Monkeytype profile")
    extra, media = {"username": data["name"]}, {}
    for source, target in (("banned", "banned"), ("isPremium", "premium")):
        if type(data.get(source)) is bool:
            extra[target] = data[source]
    if value := _text(data.get("uid")):
        extra["uid"] = value
    added = data.get("addedAt")
    if _number(added) and added <= 253402300799000:
        try:
            extra["joined"] = datetime.fromtimestamp(added / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
        except (ValueError, OverflowError, OSError):
            pass
    details = _mapping(data.get("details"))
    for key in ("bio", "keyboard"):
        if value := _text(details.get(key)):
            extra[key] = value
    socials = _mapping(details.get("socialProfiles"))
    for key in ("github", "twitter"):
        if value := _text(socials.get(key)):
            extra[key] = value
    if value := _url(socials.get("website")):
        extra["website"] = value
    discord = data.get("discordId")
    avatar = data.get("discordAvatar")
    if isinstance(discord, str) and re.fullmatch(r"[0-9]{1,25}", discord):
        extra["discord_id"] = discord
        if isinstance(avatar, str) and re.fullmatch(r"(?:a_)?[a-fA-F0-9]{32}", avatar):
            media["avatar"] = f"https://cdn.discordapp.com/avatars/{discord}/{avatar}.png"
    stats = _mapping(data.get("typingStats"))
    for obj, source, target in ((stats, "completedTests", "tests_completed"), (data, "xp", "xp"), (data, "maxStreak", "max_streak")):
        value = obj.get(source)
        if type(value) is int and value >= 0:
            extra[target] = value
    seconds = stats.get("timeTyping")
    if _number(seconds):
        extra["time_typing"] = f"{seconds / 60:.0f} minutes" if seconds < 3600 else f"{seconds / 3600:.1f} hours"
    scores = []
    for mode in _mapping(data.get("personalBests")).values():
        for entries in _mapping(mode).values():
            if isinstance(entries, list):
                scores.extend(entry["wpm"] for entry in entries if isinstance(entry, dict) and _number(entry.get("wpm")))
    if scores:
        extra["best_wpm"] = f"{max(scores):g}"
    return Result.taken(extra=extra, media=media)
