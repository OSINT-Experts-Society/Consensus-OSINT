"""Single-user MediaWiki formatversion=2 evidence."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .provider_contracts import has_service_error


def _name(value):
    if not isinstance(value, str):
        return None
    value = value.replace("_", " ").strip()
    return value[:1].upper() + value[1:]


def result(response, query, site):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("Invalid MediaWiki response")
    record = data.get("query")
    users = record.get("users") if isinstance(record, dict) and not has_service_error(record) else None
    if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
        return Result.error("No unambiguous single-user response")
    user = users[0]
    if _name(user.get("name")) != _name(query) or has_service_error(user) or "invalid" in user:
        return Result.error("Response does not identify the requested valid username")
    if user.get("missing") is True and "userid" not in user:
        return Result.available()
    if "missing" in user or type(user.get("userid")) is not int or user["userid"] <= 0:
        return Result.error("Missing or conflicting user identity")
    extra = {"userid": str(user["userid"])} if site == "wikipedia" else {"id": user["userid"]}
    count = user.get("editcount")
    if type(count) is int and count >= 0:
        extra["editcount" if site == "wikipedia" else "edit_count"] = str(count) if site == "wikipedia" else count
    joined = user.get("registration")
    if isinstance(joined, str) and joined.strip():
        extra["registration" if site == "wikipedia" else "joined"] = joined
    gender = user.get("gender")
    if gender in ("male", "female", "unknown") and (site == "wikipedia" or gender != "unknown"):
        extra["gender"] = gender
    groups = user.get("groups")
    if site == "archwiki" and isinstance(groups, list) and all(isinstance(g, str) for g in groups):
        groups = [g for g in groups if g and g != "*"]
        if groups:
            extra["groups"] = ", ".join(groups)
    return Result.taken(extra=extra)
