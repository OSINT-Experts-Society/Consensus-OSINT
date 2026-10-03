"""Retained validation evidence excludes credential and control-address guesses."""
import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue, valid_token
from .models import Status
from .provider_contracts import has_service_error


def _object(response):
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) and not has_service_error(data) else None


def _bound(data, email):
    return "email" not in data or isinstance(data["email"], str) and data["email"].casefold() == email.casefold()


def _child(data, key):
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, dict) and not has_service_error(value) else None


def anonymous_token(response):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return None, reason
    auth = _child(_child(_object(response), "data"), "authAnonymous")
    token = auth.get("token") if auth is not None else None
    if not valid_token(token):
        return None, "Missing or ambiguous anonymous lookup token; no email was submitted."
    return token, None


def outcome(response, site, email):
    accepted = (200, 409) if site == "skout" else (200,)
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=accepted)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No unambiguous, query-bound email validation result was returned.")
    data = _object(response)
    if data is None or not _bound(data, email):
        return unknown
    if site == "lespark":
        message = data.get("msg")
        if isinstance(message, str) and message.strip().casefold() == "user does not exist":
            return Status.NOT_FOUND, {}, None
        return Status.UNKNOWN, {}, "A password error does not establish account existence."
    if site == "okcupid":
        record = _child(data, "data")
        auth = _child(record, "auth")
        if record is None or auth is None or not _bound(record, email) or not _bound(auth, email):
            return unknown
        if auth.get("isEmailValid") is True:
            return Status.NOT_FOUND, {}, None
        return Status.UNKNOWN, {}, "Address rejection does not establish an account; no unrelated control address was queried."
    if site == "skout":
        code = data.get("statusCode")
        message = data.get("statusMessage")
        if response.status_code == 409:
            if (isinstance(message, str) and message.strip().casefold() == "email already exists"
                    and ("statusCode" not in data or type(code) is int and code == 409)):
                return Status.FOUND, {}, None
        elif type(code) is int and code == 200 and (
                message is None or isinstance(message, str) and message.strip().casefold() in ("", "ok", "success")):
            return Status.NOT_FOUND, {}, None
    return unknown
