"""Retained Twitter email availability; no current live-service claim."""
import hashlib
import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(response, query):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No valid, email-bound Twitter availability flag was returned.")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict) or has_service_error(data) or type(data.get("taken")) is not bool:
        return unknown
    if "valid" in data and data["valid"] is not True:
        return unknown
    if "email" in data and (not isinstance(data["email"], str) or data["email"].casefold() != query.casefold()):
        return unknown
    return (Status.FOUND if data["taken"] else Status.NOT_FOUND), {}, None


def shipped_rule(entry):
    """Bind the override to the recorded request, detection and extraction fields."""
    if entry.get("id") != "twitter":
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == "d81a9475a87be885ef14cc42e5b0abe8d09d8e8c0d158ed17bc6d7908218a06b"
