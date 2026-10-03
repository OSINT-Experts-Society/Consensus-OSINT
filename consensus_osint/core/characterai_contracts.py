"""Character.AI public-profile response and bounded optional character statistics."""

import json
from datetime import datetime, timezone
from urllib.parse import quote

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text
from .provider_contracts import has_service_error


def _dates(characters, key):
    values = []
    for item in characters:
        value = _text(item.get(key))
        if value is None:
            return []
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                if len(value) != 10:
                    return []
                parsed = parsed.replace(tzinfo=timezone.utc)
            values.append((parsed, value))
        except ValueError:
            return []
    return values


def result(response, user):
    # Inspect challenges before the narrowly retained HTTP500/wrapped404 contract.
    inspected_status = 200 if response.status_code == 500 else response.status_code
    issue, reason = http_issue(inspected_status, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict):
        return Result.error("No Character.AI response object")
    if response.status_code == 500 and set(data) == {"error"}:
        error = data.get("error")
        wrapped = error.get("json") if isinstance(error, dict) else None
        detail = wrapped.get("data") if isinstance(wrapped, dict) else None
        upstream = detail.get("axiosErrorData") if isinstance(detail, dict) else None
        if (isinstance(upstream, dict) and detail.get("path") == "social.publicProfile"
                and type(upstream.get("upstreamStatus")) is int and upstream["upstreamStatus"] == 404):
            return Result.available()
    if response.status_code != 200:
        return Result.error("Character.AI request failed")
    profile = data
    for key in ("result", "data", "json"):
        if not isinstance(profile, dict) or has_service_error(profile):
            return Result.error("No successful Character.AI profile envelope")
        profile = profile.get(key)
    if (not isinstance(profile, dict) or has_service_error(profile)
            or not isinstance(profile.get("username"), str) or profile["username"] != user):
        return Result.error("No matching Character.AI username")
    extra, media = {"username": user}, {}
    for source, target in (("name", "fullname"), ("bio", "bio"), ("subscription_type", "subscription")):
        if value := _text(profile.get(source)):
            extra[target] = value
    for source, target in (("num_followers", "followers"), ("num_following", "following")):
        if type(profile.get(source)) is int and profile[source] >= 0:
            extra[target] = profile[source]
    characters = profile.get("characters")
    if isinstance(characters, list) and all(isinstance(item, dict) and not has_service_error(item) for item in characters):
        extra["characters_returned"] = len(characters)
        for source, target in (("participant__num_interactions", "interactions_returned"), ("upvotes", "upvotes_returned")):
            if all(type(item.get(source)) is int and item[source] >= 0 for item in characters):
                extra[target] = sum(item[source] for item in characters)
        owners = [item.get("user_id") for item in characters]
        if owners and all((_text(value) or (type(value) is int and value > 0)) for value in owners) and len({str(v) for v in owners}) == 1:
            extra["characters_user_id"] = str(owners[0])
        if dates := _dates(characters, "created"):
            extra["first_returned_character_created"] = min(dates)[1]
        if dates := _dates(characters, "updated"):
            extra["last_returned_character_updated"] = max(dates)[1]
    if avatar := _text(profile.get("avatar_file_name")):
        media["avatar"] = "https://characterai.io/i/200/static/avatars/" + quote(avatar, safe="") + "?anim=0"
    return Result.taken(extra=extra, media=media)
