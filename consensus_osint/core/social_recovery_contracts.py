"""Explicit missing-account errors; sending a code does not prove an account."""

import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(response, site, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 400))
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "Recovery acknowledgment does not establish account status")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict):
        return unknown

    def matching(record):
        return (
            "email" not in record or isinstance(record["email"], str) and record["email"].casefold() == email.casefold()
        )

    remainder = {k: v for k, v in data.items() if k != "error"}
    if not matching(data) or has_service_error(remainder):
        return unknown
    if response.status_code != 400 or data.get("success") not in (None, False, "") or "password_renewal_id" in data:
        return unknown
    error = data.get("error")
    if site == "slowly" and error == "email_not_found":
        return Status.NOT_FOUND, {}, None
    if site == "superlive" and isinstance(error, dict) and matching(error) and not has_service_error(error):
        code = error.get("code")
        message = error.get("message")
        if code == 12 or isinstance(message, str) and message.casefold().strip(".!") == "attempt limit reached":
            return Status.RATE_LIMITED, {}, "Rate limited by SuperLive"
        if isinstance(message, str) and message.casefold().strip(".!") == "no registered users with this email":
            return Status.NOT_FOUND, {}, None
    return unknown
