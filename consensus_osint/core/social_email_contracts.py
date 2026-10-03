"""Retained social-service response contracts, independent of live availability."""
import json

from .email_validation import _unique_object, duplicate_message
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(site, response, email):
    if site == "myspace":
        return duplicate_message(response, "This email address was already used to create an account.")
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No valid, email-bound account lookup marker was returned.")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict) or has_service_error(data):
        return unknown
    body = data.get("data") if site == "imgur" else data
    if not isinstance(body, dict) or has_service_error(body):
        return unknown
    for obj in (data, body):
        if "email" in obj and (not isinstance(obj["email"], str) or obj["email"].casefold() != email.casefold()):
            return unknown
    if site == "imgur":
        if "invalid email domain" in response.text.lower() or type(body.get("available")) is not bool:
            return unknown
        return (Status.NOT_FOUND if body["available"] else Status.FOUND), {}, None
    if site == "vsco":
        if body.get("email_status") == "has_account":
            return Status.FOUND, {}, None
        if body.get("email_status") == "no_account":
            return Status.NOT_FOUND, {}, None
    return unknown
