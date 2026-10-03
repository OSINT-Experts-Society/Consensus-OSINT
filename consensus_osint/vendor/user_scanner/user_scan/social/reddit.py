import html
import json
import math
import re
from datetime import datetime, timezone
from urllib.parse import quote

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.named_user_contracts import _text, _url
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request
from consensus_osint.vendor.user_scanner.core.result import Result

BASE_URL = "https://www.reddit.com"
AVAILABLE_URL = f"{BASE_URL}/api/username_available.json"
BOOLEAN_FLAGS = {"is_employee": "employee", "is_mod": "moderator", "is_gold": "premium", "has_verified_email": "has_verified_email"}
KARMA_FIELDS = {"total_karma": "karma_total", "link_karma": "karma_post", "comment_karma": "karma_comment", "awardee_karma": "karma_awardee", "awarder_karma": "karma_awarder"}


def validate_reddit(user):
    show_url = f"{BASE_URL}/user/{quote(user, safe='')}/"
    try:
        response = impersonate_request(AVAILABLE_URL, params={"user": user}, allow_redirects=False)
        issue, reason = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return Result.error(reason, url=show_url)
        available = json.loads(response.text, object_pairs_hook=_unique_object)
        if type(available) is not bool:
            return Result.error("No typed Reddit availability response", url=show_url)
    except Exception as exc:
        return Result.error(exc, url=show_url)
    extra = {"available": available, "scope": "Username availability; not proof of a current account or public profile"}
    if available:
        return Result.available(extra=extra, url=show_url)
    profile, media = _profile(user)
    extra.update(profile)
    return Result.taken(extra=extra, media=media, url=show_url)


def _profile(user):
    try:
        response = impersonate_request(f"{BASE_URL}/user/{quote(user, safe='')}/about.json", allow_redirects=False)
        issue, _ = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return {}, {}
        body = json.loads(response.text, object_pairs_hook=_unique_object)
        if not isinstance(body, dict) or has_service_error(body) or ("kind" in body and body["kind"] != "t2"):
            return {}, {}
        data = body.get("data")
        if not isinstance(data, dict) or has_service_error(data):
            return {}, {}
        name = data.get("name")
        if not isinstance(name, str) or name.casefold() != user.casefold():
            return {}, {}
        extra = {"name": name, "profile_confirmed": True, "scope": "Matching Reddit profile; not proof of ownership"}
        if data.get("is_suspended") is True:
            return {**extra, "status": "suspended"}, {}
        if "is_suspended" in data and type(data["is_suspended"]) is not bool:
            return {}, {}
        if data.get("is_suspended") is False:
            extra["is_suspended"] = False
        details, media = _extract(data)
        return {**extra, **details}, media
    except Exception:
        return {}, {}


def _created_at(value):
    if type(value) not in (int, float) or not 0 <= value <= 253402300799 or not math.isfinite(value):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, OverflowError, OSError):
        return None


def _extract(data):
    profile = data.get("subreddit")
    if not isinstance(profile, dict) or has_service_error(profile):
        profile = {}
    extra, media = {}, {}
    if isinstance(data.get("id"), str) and re.fullmatch(r"[a-z0-9]+", data["id"]):
        extra["id"] = "t2_" + data["id"]
    for source, target in (("title", "display_name"), ("public_description", "bio")):
        if value := _text(profile.get(source)):
            extra[target] = value
    if value := _created_at(data.get("created_utc")):
        extra["created"] = value
    for source, target in KARMA_FIELDS.items():
        if type(data.get(source)) is int:
            extra[target] = data[source]
    for source, target in BOOLEAN_FLAGS.items():
        if type(data.get(source)) is bool:
            extra[target] = data[source]
    if type(profile.get("over_18")) is bool:
        extra["nsfw"] = profile["over_18"]
    for target, values in (("avatar", (data.get("icon_img"), profile.get("icon_img"))), ("snoovatar", (data.get("snoovatar_img"),)), ("banner", (profile.get("banner_img"),))):
        for raw in values:
            if isinstance(raw, str) and (value := _url(html.unescape(raw))):
                media[target] = value
                break
    return extra, media
