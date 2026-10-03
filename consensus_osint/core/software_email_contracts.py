"""Retained software-service email contracts, not current live verification."""
import json
import re

from .email_validation import _unique_object
from .mailbox_contracts import hidden_fields, http_issue, valid_token
from .models import Status
from .provider_contracts import has_service_error


def prerequisite(site, response):
    status, reason = http_issue(response.status_code, response.headers, response.text)
    if status is not None:
        return None, (status, {}, reason)
    names = ("csrfmiddlewaretoken",) if site == "rocketreach" else ("_sourcePage", "__fp")
    fields = hidden_fields(response.text, names)
    if fields is not None and site == "evernote":
        for name in ("hpts", "hptsh"):
            pattern = r'document\.getElementById\("' + name + r'"\)\.value\s*=\s*"([^"\r\n]*)"'
            values = re.findall(pattern, response.text)
            if len(values) != 1 or not valid_token(values[0]):
                fields = None
                break
            fields[name] = values[0]
    if fields is None:
        return None, (Status.UNKNOWN, {}, "Missing or ambiguous lookup prerequisite; no email was submitted.")
    return fields, None


def outcome(site, response, email):
    status, reason = http_issue(response.status_code, response.headers, response.text)
    if status is not None:
        return status, {}, reason
    unknown = (Status.UNKNOWN, {}, "No supported, email-bound account marker was returned.")
    if site == "lastpass":
        if response.text == "no":
            return Status.FOUND, {}, None
        if response.text == "ok":
            return Status.NOT_FOUND, {}, None
        if response.text == "emailinvalid":
            return Status.UNKNOWN, {}, "Provider rejected the email format; this does not establish account absence."
        return unknown
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict) or has_service_error(data):
        return unknown
    for key in ("email", "email_address", "username"):
        if key in data and (not isinstance(data[key], str) or data[key].casefold() != email.casefold()):
            return unknown
    if site == "rocketreach" and type(data.get("found")) is bool:
        return (Status.FOUND if data["found"] else Status.NOT_FOUND), {}, None
    if site == "issuu" and isinstance(data.get("status"), str):
        if data["status"] == "unavailable":
            return Status.FOUND, {}, None
        if data["status"] == "available":
            return Status.NOT_FOUND, {}, None
    if site == "evernote" and data.get("usePasswordAuth") is True and not data.get("displayMessage"):
        return Status.FOUND, {}, None
    return unknown
