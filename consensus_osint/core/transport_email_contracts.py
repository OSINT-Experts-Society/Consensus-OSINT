"""Typed retained transport/shopping lookup replies; no live-service claim."""
import json
import re

from .email_validation import _unique_object
from .mailbox_contracts import http_issue, valid_token
from .models import Status
from .provider_contracts import has_service_error


def page_token(response, field):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return None, (issue, {}, reason)
    values = re.findall(r'"' + re.escape(field) + r'"\s*:\s*("(?:\\.|[^"\\])*")', response.text)
    token = None
    if len(values) == 1:
        try:
            token = json.loads(values[0])
        except ValueError:
            pass
    if not valid_token(token):
        return None, (Status.UNKNOWN, {}, "Missing or ambiguous app token; no identifier lookup was submitted.")
    return token, None


def outcome(site, response, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text,
                               accepted=(204, 409) if site == "nike" else (200,))
    if issue is not None:
        return issue, {}, reason
    if site == "nike":
        return (Status.FOUND if response.status_code == 409 else Status.NOT_FOUND), {}, None
    unknown = (Status.UNKNOWN, {}, "No unambiguous account marker was returned for the queried email.")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if site in ("dominosfr", "garmin"):
        if type(data) is bool:
            return (Status.NOT_FOUND if data else Status.FOUND), {}, None
        return unknown
    if not isinstance(data, dict) or has_service_error(data):
        return unknown
    for key in ("email", "email_address", "emailAddress"):
        if key in data and (not isinstance(data[key], str) or data[key].casefold() != email.casefold()):
            return unknown
    if site == "blablacar":
        if "url" in data:
            return unknown
        field = "exists"
    elif site == "deliveroo":
        field = "registered"
    elif site == "vrbo":
        methods = data.get("authType")
        if methods == ["LOGIN_UMS"]:
            return Status.FOUND, {}, None
        if methods == ["SIGNUP"]:
            return Status.NOT_FOUND, {}, None
        return unknown
    else:
        return unknown
    if type(data.get(field)) is bool:
        return (Status.FOUND if data[field] else Status.NOT_FOUND), {}, None
    return unknown
