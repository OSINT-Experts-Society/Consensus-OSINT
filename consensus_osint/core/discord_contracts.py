"""Discord signup availability and invite-code evidence, kept distinct."""
import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .provider_contracts import has_service_error


def availability(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        body = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous Discord availability JSON")
    if not isinstance(body, dict) or has_service_error(body) or type(body.get("taken")) is not bool:
        return Result.error("No successful typed Discord availability response")
    if "username" in body and body["username"] != user:
        return Result.error("Discord response identifies a different username")
    extra = {"available": not body["taken"], "scope": "Username availability; not proof of a current account or public profile"}
    return Result.taken(extra=extra) if body["taken"] else Result.available(extra=extra)


def invite(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        body = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous Discord invite JSON")
    if not isinstance(body, dict) or has_service_error(body):
        return Result.error("No successful Discord invite response")
    if body.get("code") != user or type(body.get("type")) is not int or body["type"] not in (0, 1, 2):
        return Result.error("No matching typed Discord invite")
    extra = {"invite_code": user, "invite_type": body["type"], "scope": "Invite code; not a matching username or account"}
    for key in ("approximate_presence_count", "approximate_member_count"):
        if type(body.get(key)) is int and body[key] >= 0:
            extra[key] = body[key]
    return Result.taken(extra=extra)
