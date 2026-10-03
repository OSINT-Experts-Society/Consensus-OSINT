"""Bound e621 user JSON; numeric route IDs alone do not identify a handle."""
import json

from consensus_osint import __version__
from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text
from .provider_contracts import has_service_error

HEADERS = {
    "User-Agent": f"Consensus/{__version__} (+https://github.com/OSINT-Experts-Society/Consensus-OSINT)",
    "Accept": "application/json",
}

COUNTERS = {
    "post_upload_count": "uploads",
    "post_update_count": "post_edits",
    "note_update_count": "note_edits",
    "comment_count": "comments",
    "favorite_count": "favorites",
    "forum_post_count": "forum_posts",
    "wiki_page_version_count": "wiki_edits",
    "artist_version_count": "artist_edits",
    "pool_version_count": "pool_edits",
    "flag_count": "flags",
    "positive_feedback_count": "positive_feedback",
    "neutral_feedback_count": "neutral_feedback",
    "negative_feedback_count": "negative_feedback",
}


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        profile = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous e621 JSON")
    if not isinstance(profile, dict) or has_service_error(profile) or profile.get("reason"):
        return Result.error("No successful e621 user object")
    name = profile.get("name")
    if (not isinstance(name, str) or not name or name.casefold() != user.casefold()
            or type(profile.get("id")) is not int or profile["id"] <= 0):
        return Result.error("e621 returned identity does not match the requested handle")
    extra = {"username": name, "user_id": profile["id"]}
    for key, label in (("level_string", "level"), ("created_at", "joined"),
                       ("profile_about", "about"), ("profile_artinfo", "artist_info")):
        if value := _text(profile.get(key)):
            extra[label] = value
    for key in ("is_banned", "is_verified"):
        if type(profile.get(key)) is bool:
            extra[key] = profile[key]
    for key, label in COUNTERS.items():
        if type(profile.get(key)) is int and profile[key] >= 0:
            extra[label] = profile[key]
    avatar = profile.get("avatar_id")
    if type(avatar) is int and avatar > 0:
        extra["avatar_post"] = f"https://e621.net/posts/{avatar}"
    return Result.taken(extra=extra)
