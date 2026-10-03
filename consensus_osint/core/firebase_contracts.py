"""Existing Firebase lookup signals; no authentication or reset delivery proof.

Google's email-enumeration protection deliberately makes reset acknowledgments
ambiguous. Explicit legacy errors and typed registration flags retain their
documented scope; missing fields never imply account absence.
"""
from __future__ import annotations

from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import email_flag_outcome, has_service_error


def outcome(flow, response, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 400))
    if issue is not None:
        return issue, {}, reason
    unknown = "Unrecognized or conflicting Firebase response; account status is unknown."
    try:
        data = response.json()
    except (ValueError, TypeError):
        data = None
    if not isinstance(data, dict):
        return Status.UNKNOWN, {}, unknown
    if "email" in data and (not isinstance(data["email"], str) or data["email"].casefold() != email.casefold()):
        return Status.UNKNOWN, {}, unknown
    if flow == "auth":
        # Provider/sign-in lists are optional. An empty list alone is not a
        # negative; nonempty lists conflict with an explicit negative flag.
        if data.get("registered") is False and (
                data.get("signinMethods") or data.get("allProviders") or data.get("forExistingProvider") is True):
            return Status.UNKNOWN, {}, unknown
        return email_flag_outcome(response, "registered", email)
    if flow not in {"password", "reset"}:
        return Status.UNKNOWN, {}, unknown
    if response.status_code == 400:
        error = data.get("error")
        other = {key: value for key, value in data.items() if key != "error"}
        if (not isinstance(error, dict) or has_service_error(other)
                or any(key in data for key in ("registered", "idToken", "refreshToken", "localId", "kind"))
                or ("code" in error and (type(error["code"]) is not int or error["code"] != 400))):
            return Status.UNKNOWN, {}, unknown
        message = error.get("message")
        details = error.get("errors", [])
        if (not isinstance(details, list) or any(not isinstance(item, dict)
                or ("message" in item and item["message"] != message) for item in details)):
            return Status.UNKNOWN, {}, unknown
        if message == "EMAIL_NOT_FOUND":
            return Status.NOT_FOUND, {}, None
        if flow == "password" and message == "INVALID_PASSWORD":
            return Status.FOUND, {}, None
        if message == "INVALID_LOGIN_CREDENTIALS":
            return Status.UNKNOWN, {}, "Firebase hides whether the email or password is invalid; account status is unknown."
    elif flow == "reset" and not has_service_error(data) and (
            data.get("kind") == "identitytoolkit#GetOobConfirmationCodeResponse" or isinstance(data.get("email"), str)):
        return Status.UNKNOWN, {}, ("Password-reset request acknowledged; this response does not establish whether "
                                    "the email is registered or a message was sent.")
    # Never retain an unexpected successful sign-in's tokens/profile data.
    return Status.UNKNOWN, {}, unknown


def native_result(flow, response, email, url):
    from ..vendor.user_scanner.core.result import Result

    status, _, reason = outcome(flow, response, email)
    if status is Status.FOUND:
        return Result.taken(url=url)
    if status is Status.NOT_FOUND:
        return Result.available(url=url)
    return Result.error(reason, url=url)


def shipped_reset_rule(entry):
    """Only the two recorded translations inherit the reset interpretation.

    Fingerprints cover the entire request and detection contract, including app
    key, package headers and payload. Custom routes/options retain their rules.
    """
    import hashlib
    import json

    fingerprints = {
        "bnrlanguages-email": "3d6f948db0e9e9840fa5b67487c15480745a74d70327c36dd894eb9ea441891e",
        "bunpo-email": "5144a445b6a4c4773e89c6c53baada943462fe168ee2d8e6f84d0e6f2d84993f",
    }
    expected = fingerprints.get(entry.get("id"))
    if expected is None:
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == expected
