"""Coherent email availability responses; no claim of live provider reliability."""
import json
import re

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(response, site, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No coherent email-availability response")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict):
        return unknown
    if "email" in data and (not isinstance(data["email"], str) or data["email"].casefold() != email.casefold()):
        return unknown
    excluded = {"status"} if site == "fitnessblender" else {"error"} if site == "neocities" else set()
    if has_service_error({key: value for key, value in data.items() if key not in excluded}):
        return unknown
    if site == "chess_com":
        status = data.get("status")
        if status in ("EMAIL_STATUS_TAKEN", "EMAIL_STATUS_AVAILABLE"):
            return (Status.FOUND if status == "EMAIL_STATUS_TAKEN" else Status.NOT_FOUND), {}, None
    elif site == "fitnessblender":
        message = data.get("message")
        if data.get("status") == "success" and message == "ok":
            return Status.NOT_FOUND, {}, None
        if data.get("status") == "error" and isinstance(message, str) and re.fullmatch(
                r"(?:(?:this |the )?email(?: address)? (?:is )?)?already registered[.!]?", message, re.I):
            return Status.FOUND, {}, None
    elif site == "neocities":
        if "error" in data:
            if "result" in data:
                return unknown
            message = data["error"]
            if isinstance(message, str) and re.fullmatch(
                    r"(?:(?:this |the )?email(?: address)? )?already exists[.!]?", message, re.I):
                return Status.FOUND, {}, None
        elif data.get("result") == "ok":
            return Status.NOT_FOUND, {}, None
    return unknown
