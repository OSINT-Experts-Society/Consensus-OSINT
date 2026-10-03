"""Guard a single Twitch ChannelLayout response and its optional metadata."""

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
        rows = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        rows = None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict) or has_service_error(rows[0]):
        return Result.error("No single successful Twitch operation response")
    data = rows[0].get("data")
    profile = data.get("user") if isinstance(data, dict) else None
    if not isinstance(profile, dict) or has_service_error(data) or has_service_error(profile):
        return Result.error("No coherent Twitch user result")
    login = profile.get("login")
    if "login" in profile and (not isinstance(login, str) or login.casefold() != user.casefold()):
        return Result.error("Returned Twitch login conflicts with requested user")
    typename = profile.get("__typename")
    if typename == "UserDoesNotExist":
        if any(profile.get(key) is not None for key in ("id", "description", "channel")):
            return Result.error("Conflicting Twitch missing-user response")
        return Result.available()
    if typename != "User" or not _text(profile.get("id")):
        return Result.error("No typed Twitch user identity")
    extra = {"id": profile["id"], "username": login or user}
    if value := _text(profile.get("description")):
        extra["description"] = value
    followers = profile.get("followers")
    if isinstance(followers, dict) and not has_service_error(followers):
        count = followers.get("totalCount")
        if type(count) is int and count >= 0:
            extra["followers"] = count
    channel = profile.get("channel")
    socials = channel.get("socialMedias") if isinstance(channel, dict) and not has_service_error(channel) else None
    if isinstance(socials, list):
        links = []
        for social in socials:
            if isinstance(social, dict) and (url := _url(social.get("url"))):
                name = _text(social.get("name"))
                links.append(f"{name}: {url}" if name else url)
        if links:
            extra["social_links"] = links
    return Result.taken(extra=extra)
