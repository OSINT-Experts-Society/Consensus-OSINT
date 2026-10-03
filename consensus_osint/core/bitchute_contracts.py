"""BitChute channel identity and typed optional fields."""
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
        return Result.error("Invalid or ambiguous BitChute JSON")
    if not isinstance(body, dict) or has_service_error(body) or body.get("channel_id") != user:
        return Result.error("No successful matching BitChute channel")
    extra = {"channel_id": user, "scope": "Channel ID; not proof of a same-named user account or ownership"}
    for key, target in (("channel_name", "name"), ("description", "description")):
        if value := _text(body.get(key)):
            extra[target] = value
    for key, target in (("subscriber_count", "subscribers"), ("video_count", "videos")):
        if type(body.get(key)) is int and body[key] >= 0:
            extra[target] = body[key]
    return Result.taken(extra=extra)
