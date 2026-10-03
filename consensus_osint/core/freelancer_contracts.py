"""Query-bound Freelancer user evidence and typed optional metadata."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No successful Freelancer response")
    payload = data.get("result")
    if not isinstance(payload, dict) or has_service_error(payload):
        return Result.error("No coherent Freelancer result")
    users = payload.get("users")
    if not isinstance(users, dict) or not users:
        return Result.error("No matching user evidence")
    matches = [item for item in users.values() if isinstance(item, dict)
               and isinstance(item.get("username"), str) and item["username"].casefold() == user.casefold()]
    if len(matches) != 1:
        return Result.error("No unique matching Freelancer username")
    item = matches[0]
    uid = item.get("id")
    if has_service_error(item) or not (_text(uid) or (type(uid) is int and uid > 0)):
        return Result.error("No typed successful Freelancer user")
    extra = {"id": uid, "username": item["username"]}
    for key in ("display_name", "role"):
        if value := _text(item.get(key)):
            extra[key] = value
    registered = item.get("registration_date")
    if type(registered) is int and registered >= 0:
        extra["registration_date"] = registered
    location = item.get("location")
    if isinstance(location, dict) and not has_service_error(location):
        country = location.get("country")
        country_name = _text(country.get("name")) if isinstance(country, dict) and not has_service_error(country) else None
        city = _text(location.get("city"))
        parts = [part for part in (city, country_name) if part]
        if parts:
            extra["location"] = ", ".join(parts)
    return Result.taken(extra=extra)
