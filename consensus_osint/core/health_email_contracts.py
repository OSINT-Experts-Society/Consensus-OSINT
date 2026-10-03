"""Account/backup response contracts; no health or activity inference."""

import json
from urllib.parse import urlsplit

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(response, site, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No coherent account response")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (ValueError, TypeError):
        return unknown
    if not isinstance(data, dict):
        return unknown
    remainder = {k: v for k, v in data.items() if not (site == "womanlog" and k == "error_code")}
    if (
        has_service_error(remainder)
        or "email" in data
        and (not isinstance(data["email"], str) or data["email"].casefold() != email.casefold())
    ):
        return unknown
    if site == "womanlog":
        if data.get("error_code") == "EMAIL_NOT_FOUND" and data.get("success") is not True:
            return Status.NOT_FOUND, {}, None
        return unknown
    if site == "myperiodtracker":
        scope = {"scope": "Backup account lookup; does not establish health information or app activity"}
        if data.get("status") == "NoAccount":
            return Status.NOT_FOUND, scope, None
        if data.get("status") == "Success":
            return Status.FOUND, scope, None
    if site == "femometer":
        user_id = data.get("userId")
        location = data.get("userLocation")
        if type(user_id) is int and user_id == 0 and type(location) is int and location == 0:
            return Status.NOT_FOUND, {}, None
        if type(user_id) is int and user_id > 0:
            extra = {
                "user id": user_id,
                "scope": "Account routing only; does not establish health information or activity",
            }
            server = data.get("url")
            if isinstance(server, str) and not any(ord(c) <= 32 or ord(c) == 127 for c in server):
                try:
                    parsed = urlsplit(server)
                    host = parsed.hostname or ""
                    if (
                        parsed.scheme == "https"
                        and not parsed.username
                        and not parsed.password
                        and (host == "femometer.com" or host.endswith(".femometer.com"))
                    ):
                        extra["server location"] = server
                except ValueError:
                    pass
            return Status.FOUND, extra, None
    return unknown
