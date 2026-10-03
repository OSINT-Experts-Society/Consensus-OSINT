"""Typed AtCoder availability and bound Bugcrowd public profile evidence."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def result(response, site, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    if site == "atcoder":
        if response.text.strip() == "true":
            return Result.taken()
        if response.text.strip() == "false":
            return Result.available()
        return Result.error("No literal username-existence boolean")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (ValueError, TypeError):
        data = None
    if site in ("devhunt", "hackernoon", "hackerrank"):
        if site == "devhunt":
            record = data[0] if isinstance(data, list) and len(data) == 1 else None
            key = "username"
        else:
            if not isinstance(data, dict) or has_service_error(data):
                return Result.error("No coherent profile envelope")
            record = data.get("profile" if site == "hackernoon" else "model")
            key = "handle" if site == "hackernoon" else "username"
        if (
            not isinstance(record, dict)
            or has_service_error(record)
            or not isinstance(record.get(key), str)
            or (record[key] != user if site == "devhunt" else record[key].casefold() != user.casefold())
        ):
            return Result.error("No matching public profile; an empty response is inconclusive")
        if site == "hackerrank" and (type(record.get("id")) is not int or record["id"] <= 0):
            return Result.error("No valid profile identifier")
        if site == "devhunt" and not _text(record.get("id")):
            return Result.error("No valid profile identifier")
        extra, media = {"username": record[key]}, {}
        mapping = {
            "devhunt": {
                "full_name": "fullname",
                "headline": "headline",
                "about": "bio",
                "id": "owner_id",
                "updated_at": "updated_at",
            },
            "hackernoon": {"displayName": "name", "bio": "bio", "location": "location"},
            "hackerrank": {key: key for key in ("country", "school", "created_at", "company")},
        }[site]
        for source, target in mapping.items():
            if value := _text(record.get(source)):
                extra[target] = value
        for source, target in (
            (("totalStories", "stories"),)
            if site == "hackernoon"
            else (("id", "id"), ("level", "level"))
            if site == "hackerrank"
            else ()
        ):
            if type(record.get(source)) is int and record[source] >= 0:
                extra[target] = record[source]
        for source, target in (("website_url", "website"), ("social_url", "social_link")) if site == "devhunt" else ():
            if value := _url(record.get(source)):
                extra[target] = value
        avatar = "avatar_url" if site == "devhunt" else "avatar"
        if value := _url(record.get(avatar)):
            media["avatar"] = value
        if site == "devhunt" and isinstance(record.get("products"), list):
            names = [
                value for item in record["products"] if isinstance(item, dict) and (value := _text(item.get("name")))
            ]
            if names:
                extra["launched_tools"] = names
        if site == "hackernoon" and isinstance(record.get("socialMedia"), dict):
            for key, raw in record["socialMedia"].items():
                if isinstance(key, str) and key.isidentifier() and (value := _url(raw)):
                    extra["social_" + key] = value
        return Result.taken(extra=extra, media=media)
    if (
        not isinstance(data, dict)
        or has_service_error(data)
        or not isinstance(data.get("username"), str)
        or data["username"].casefold() != user.casefold()
    ):
        return Result.error("No matching public profile; generic absence does not establish account status")
    extra, media = {"public": True, "username": data["username"]}, {}
    for source, target in (("countryCode", "country"), ("twitterUsername", "twitter"), ("biography", "bio")):
        if value := _text(data.get(source)):
            extra[target] = value
    for source, target in (("linkedinUrl", "linkedin"), ("website", "website")):
        if value := _url(data.get(source)):
            extra[target] = value
    if type(data.get("identityVerified")) is bool:
        extra["verified"] = data["identityVerified"]
    for source, target in (("avatarUrl", "avatar"), ("bannerImageUrl", "banner")):
        if value := _url(data.get(source)):
            media[target] = value
    return Result.taken(extra=extra, media=media)
