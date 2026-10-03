"""Bound public user API objects and independently typed optional metadata."""

import json
from urllib.parse import urlsplit

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .provider_contracts import has_service_error


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _url(value):
    if not _text(value) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme in ("https", "http") and parsed.hostname and not parsed.username and not parsed.password:
            return value
    except ValueError:
        pass
    return None


def result(response, site, query):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No coherent user object")
    username = data.get("login" if site in ("gitee", "githubgist") else "username")
    identity = data.get("player_id" if site == "chess_com" else "id")
    valid_identity = (
        (type(identity) is int and identity > 0)
        if site in ("scratch", "chess_com", "gitee", "githubgist")
        else bool(_text(identity))
    )
    if site == "hex_pm":
        valid_identity = True  # This route identifies its user by the username field.
    if not isinstance(username, str) or not username or username.casefold() != query.casefold() or not valid_identity:
        return Result.error("User identity does not match the requested username")
    if site == "lichess" and identity.casefold() != query.casefold():
        return Result.error("Lichess user id does not match the requested username")
    extra = {"username": username}
    if site != "hex_pm":
        extra["user_id"] = identity
    media = {}
    if site == "codewars":
        extra["id"] = identity
        for key in ("name", "clan"):
            if value := _text(data.get(key)):
                extra[key] = value
        for source, target in (("honor", "honor"), ("leaderboardPosition", "leaderboard_position")):
            if type(data.get(source)) is int and data[source] >= 0:
                extra[target] = data[source]
        ranks = data.get("ranks")
        overall = ranks.get("overall") if isinstance(ranks, dict) else None
        if isinstance(overall, dict):
            if value := _text(overall.get("name")):
                extra["rank_name"] = value
            if type(overall.get("score")) is int and overall["score"] >= 0:
                extra["score"] = overall["score"]
    elif site == "modrinth":
        for key in ("name", "role", "bio", "created"):
            if value := _text(data.get(key)):
                extra[key] = value
        if value := _url(data.get("avatar_url")):
            media["avatar"] = value
    elif site == "lichess":
        profile = data.get("profile")
        links = []
        if isinstance(profile, dict):
            for source, target in (("realName", "name"), ("bio", "bio")):
                if value := _text(profile.get(source)):
                    extra[target] = value
            if value := _text(profile.get("links")):
                links.append(value)
        streamer = data.get("streamer")
        if isinstance(streamer, dict):
            for service in ("twitch", "youtube"):
                account = streamer.get(service)
                if isinstance(account, dict) and (value := _url(account.get("channel"))):
                    links.append(value)
        if links:
            extra["links"] = ", ".join(dict.fromkeys(links))
        for key in ("patron", "verified"):
            if type(data.get(key)) is bool:
                extra[key] = "Yes" if data[key] else "No"
    elif site == "hex_pm":
        for source, target in (("full_name", "name"), ("email", "email"), ("inserted_at", "joined")):
            if value := _text(data.get(source)):
                extra[target] = value
        handles = data.get("handles")
        if isinstance(handles, dict):
            for key in ("github", "twitter"):
                if value := _text(handles.get(key)):
                    extra[key] = value
    elif site == "scratch":
        extra["id"] = str(identity)
        history = data.get("history")
        if isinstance(history, dict) and (value := _text(history.get("joined"))):
            extra["joined"] = value
        profile = data.get("profile")
        if isinstance(profile, dict):
            if value := _text(profile.get("country")):
                extra["country"] = value
            images = profile.get("images")
            if isinstance(images, dict) and (value := _url(images.get("90x90"))):
                media["avatar"] = value
    elif site == "chess_com":
        for key in ("name", "title", "status", "league", "location"):
            if value := _text(data.get(key)):
                extra[key] = value
        if type(data.get("followers")) is int and data["followers"] >= 0:
            extra["followers"] = str(data["followers"])
        if value := _url(data.get("avatar")):
            media["avatar"] = value
        if value := _url(data.get("twitch_url")):
            extra["links"] = value
    elif site in ("gitee", "githubgist"):
        extra["id"] = identity
        extra["login"] = username
        for key in ("name", "bio", "location", "blog"):
            if value := _text(data.get(key)):
                extra[key] = value
        for key in ("public_repos", "followers", "following", "public_gists"):
            if type(data.get(key)) is int and data[key] >= 0:
                extra[key] = data[key]
        if site == "githubgist":
            extra["scope"] = "GitHub account; does not establish published Gists"
            if value := _text(data.get("created_at")):
                extra["joined"] = value
    return Result.taken(extra=extra, media=media)
