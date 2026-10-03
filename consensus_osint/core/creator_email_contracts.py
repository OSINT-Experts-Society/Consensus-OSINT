"""Retained creator validation routes with explicit response and query guards."""
import json
import re

from .email_validation import _unique_object
from .mailbox_contracts import http_issue, valid_token
from .models import Status
from .provider_contracts import has_service_error


def _data(response):
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _bound(data, email):
    return all(key not in data or isinstance(data[key], str) and data[key].casefold() == email.casefold()
               for key in ("email", "email_address", "L"))


def vimeo_token(response):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return None, reason
    data = _data(response)
    if data is None or has_service_error(data) or not valid_token(data.get("xsrft")):
        return None, "Missing or ambiguous Vimeo lookup token; no email was submitted."
    return data["xsrft"], None


def outcome(response, site, email):
    accepted = (204, 422) if site == "kick" else (200,)
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=accepted)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No coherent, query-bound creator lookup result was returned.")
    if site == "kick" and response.status_code == 204:
        return (Status.NOT_FOUND, {}, None) if not response.text.strip() else unknown
    data = _data(response)
    if data is None or not _bound(data, email):
        return unknown
    if site == "kick":
        if has_service_error({key: value for key, value in data.items() if key != "errors"}):
            return unknown
        errors = data.get("errors")
        if not isinstance(errors, dict) or set(errors) != {"email"}:
            return unknown
        messages = errors["email"]
        if (isinstance(messages, list) and len(messages) == 1 and isinstance(messages[0], str)
                and re.fullmatch(r"(?:(?:the )?email (?:address )?has )?already been taken[.!]?", messages[0], re.I)):
            return Status.FOUND, {}, None
        return unknown
    if has_service_error(data):
        return unknown
    if site == "canva":
        action = data.get("B")
        if isinstance(action, dict) and not has_service_error(action) and _bound(action, email):
            if action.get("A?") in ("A", "B"):
                return (Status.FOUND if action["A?"] == "A" else Status.NOT_FOUND), {}, None
    if site == "figma":
        meta = data.get("meta")
        if not isinstance(meta, dict) or has_service_error(meta) or not _bound(meta, email):
            return unknown
        methods = meta.get("available_methods")
        if not isinstance(methods, list) or not methods or any(not isinstance(m, str) or not m for m in methods):
            return unknown
        if len(set(methods)) != len(methods):
            return unknown
        steps = set(methods) & {"sign_in", "sign_up"}
        if len(steps) == 1:
            return (Status.FOUND if "sign_in" in steps else Status.NOT_FOUND), {}, None
    if site == "patreon":
        record = data.get("data")
        if not isinstance(record, dict) or has_service_error(record) or not _bound(record, email):
            return unknown
        attributes = record.get("attributes")
        if not isinstance(attributes, dict) or has_service_error(attributes) or not _bound(attributes, email):
            return unknown
        step = attributes.get("next_auth_step")
        if step in ("password", "sso_required"):
            extra = {"login_method": "SSO" if step == "sso_required" else "password"}
            providers = attributes.get("supported_sso_providers", [])
            if isinstance(providers, list) and all(isinstance(p, str) and p.strip() for p in providers):
                extra["sso_providers"] = ", ".join(providers)
            return Status.FOUND, extra, None
        if step == "signup":
            return Status.NOT_FOUND, {}, None
    if site == "vimeo":
        if data.get("has_error_user_exists") is True and not any(
                value for key, value in data.items() if key.startswith("has_error_") and key != "has_error_user_exists"):
            return Status.FOUND, {}, None
    return unknown
