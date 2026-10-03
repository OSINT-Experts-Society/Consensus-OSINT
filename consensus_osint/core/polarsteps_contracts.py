"""Polarsteps username evidence with independently typed optional fields."""

import json
import math

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _number(value):
    return type(value) in (int, float) and value >= 0 and (type(value) is int or math.isfinite(value))


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict):
        return Result.error("No Polarsteps user object")
    if data.get("error") == "api_version_too_old_for_endpoint":
        return Result.error("Polarsteps API version is no longer supported")
    if has_service_error(data):
        return Result.error("Unsuccessful Polarsteps response")
    uid = data.get("id")
    if (not isinstance(data.get("username"), str) or data["username"].casefold() != user.casefold()
            or not (_text(uid) or (type(uid) is int and uid > 0))):
        return Result.error("No matching Polarsteps username and typed ID")
    extra = {"id": uid, "username": data["username"]}
    for source, target in (("uuid", "uuid"), ("first_name", "first_name"), ("last_name", "last_name"),
                           ("description", "bio"), ("subscription_type", "subscription")):
        if value := _text(data.get(source)):
            extra[target] = value
    if type(data.get("subscription_type")) is int:
        extra["subscription"] = data["subscription_type"]
    joined = data.get("creation_date")
    if _text(joined) or _number(joined):
        extra["joined"] = joined
    if type(data.get("visibility")) is int:
        extra["visibility"] = data["visibility"]
    for source, target in (("followers", "followers_returned"), ("followees", "following_returned")):
        if isinstance(data.get(source), list):
            extra[target] = len(data[source])
    location = data.get("living_location")
    if isinstance(location, dict) and not has_service_error(location):
        for key in ("locality", "administrative_area", "country", "country_code"):
            if value := _text(location.get(key)):
                extra[key] = value
    stats = data.get("stats")
    if isinstance(stats, dict) and not has_service_error(stats):
        for source, target in (("trip_count", "trips"), ("step_count", "steps"), ("country_count", "countries"), ("like_count", "likes")):
            if type(stats.get(source)) is int and stats[source] >= 0:
                extra[target] = stats[source]
        for source, target in (("km_count", "distance_km"), ("time_traveled_in_seconds", "travel_seconds"),
                               ("world_percentage", "world_percentage"), ("furthest_place_from_home_km", "furthest_distance_km")):
            if _number(stats.get(source)):
                extra[target] = stats[source]
        for source, target in (("last_trip_end_date", "last_trip_end"), ("furthest_place_from_home_location", "furthest_place"),
                               ("furthest_place_from_home_country", "furthest_country")):
            if value := _text(stats.get(source)):
                extra[target] = value
        if _number(stats.get("last_trip_end_date")):
            extra["last_trip_end"] = stats["last_trip_end_date"]
        continents = stats.get("continents")
        if isinstance(continents, list) and continents and all(_text(value) for value in continents):
            extra["continents"] = ", ".join(continents)
    media = {}
    if value := _url(data.get("profile_image_path")):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
