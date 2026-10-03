"""Fotka request-bound profile responses and optional metadata."""
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
        return Result.error("Invalid or ambiguous Fotka JSON")
    profile = body.get("profil") if isinstance(body, dict) and not has_service_error(body) else None
    if not isinstance(profile, dict) or has_service_error(profile):
        return Result.error("No successful Fotka profile")
    identifier = profile.get("id")
    if not (type(identifier) is int and identifier > 0 or isinstance(identifier, str) and identifier.isascii() and identifier.isdigit() and identifier.strip("0")):
        return Result.error("No typed Fotka profile ID")
    for obj in (body, profile):
        if "login" in obj and (not isinstance(obj["login"], str) or obj["login"].casefold() != user.casefold()):
            return Result.error("Fotka response identifies a different login")
    extra = {"id": identifier}
    if value := _text(profile.get("city")):
        extra["city"] = value
    if value := _text(profile.get("sex")):
        extra["sex"] = value
    elif type(profile.get("sex")) is int and profile["sex"] >= 0:
        extra["sex"] = profile["sex"]
    for key in ("age", "creationTS", "photosNumber"):
        if type(profile.get(key)) is int and profile[key] >= 0:
            extra[key] = profile[key]
    return Result.taken(extra=extra)
