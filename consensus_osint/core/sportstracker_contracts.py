"""Sports Tracker username response identity and optional metadata."""
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
        body = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous Sports Tracker JSON")
    profile = body.get("payload") if isinstance(body, dict) and not has_service_error(body) else None
    if not isinstance(profile, dict) or has_service_error(profile):
        return Result.error("No successful Sports Tracker profile")
    name = profile.get("username")
    if not isinstance(name, str) or name.casefold() != user.casefold():
        return Result.error("Sports Tracker username does not match the request")
    extra = {"username": name}
    for key in ("uuid", "realName", "country", "city", "gender"):
        if value := _text(profile.get(key)):
            extra[key] = value
    for key, target in (("followersCount", "followers"), ("followingCount", "following"), ("createdDate", "createdDate")):
        if type(profile.get(key)) is int and profile[key] >= 0:
            extra[target] = profile[key]
    if value := _text(profile.get("createdDate")):
        extra["createdDate"] = value
    return Result.taken(extra=extra)
