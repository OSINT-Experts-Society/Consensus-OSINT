"""pr0gramm matching user evidence and typed profile metadata."""
import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        body = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous pr0gramm JSON")
    profile = body.get("user") if isinstance(body, dict) and not has_service_error(body) else None
    if not isinstance(profile, dict) or has_service_error(profile):
        return Result.error("No successful pr0gramm user")
    name = profile.get("name")
    identifier = profile.get("id")
    if not isinstance(name, str) or name.casefold() != user.casefold() or type(identifier) is not int or identifier <= 0:
        return Result.error("No matching typed pr0gramm user")
    extra = {"id": identifier, "name": name}
    # Scores may be signed; counts, status codes and timestamps must not be.
    if type(profile.get("score")) is int:
        extra["score"] = profile["score"]
    for key in ("registered", "mark"):
        if type(profile.get(key)) is int and profile[key] >= 0:
            extra[key] = profile[key]
    for key, target in (("commentCount", "comments"), ("uploadCount", "uploads"), ("tagCount", "tags")):
        if type(body.get(key)) is int and body[key] >= 0:
            extra[target] = body[key]
    return Result.taken(extra=extra)
