"""Small shared response contracts; these do not establish live reliability."""
from __future__ import annotations


def has_service_error(data: dict) -> bool:
    """Explicit errors take precedence over otherwise successful lookup fields."""
    keys = ("error", "Error", "errors", "errorCode", "error_code", "error_type", "error_message", "errorMessage",
            "challenge", "checkpoint_url")
    if any(key in data and data[key] is not None and data[key] is not False and data[key] != "" for key in keys):
        return True
    status = data.get("status")
    return (data.get("success") is False or data.get("ok") is False or status is False
            or isinstance(status, str) and status.casefold() in ("error", "fail", "failed"))


def email_flag_outcome(response, field: str, query: str, *, true_means_available: bool = False, path: tuple[str, ...] = ()):
    """A typed email-lookup flag is checking evidence, without profile fields."""
    import json

    from .email_validation import _unique_object
    from .mailbox_contracts import http_issue
    from .models import Status

    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (ValueError, TypeError):
        data = None
    def coherent(record):
        return isinstance(record, dict) and not has_service_error(record) and (
            "email" not in record or isinstance(record["email"], str) and record["email"].casefold() == query.casefold())
    if not coherent(data):
        return Status.UNKNOWN, {}, "Response lacks a coherent email-lookup envelope"
    for key in path:
        data = data.get(key)
        if not coherent(data):
            return Status.UNKNOWN, {}, "Response lacks a coherent email-lookup envelope"
    if type(data.get(field)) is not bool:
        return Status.UNKNOWN, {}, "Response lacks an unambiguous typed email-lookup flag"
    exists = not data[field] if true_means_available else data[field]
    return (Status.FOUND if exists else Status.NOT_FOUND), {}, None


def literal_email_outcome(response, found: str, missing: str):
    """Read exact provider literals only after transport/access checks."""
    from .mailbox_contracts import http_issue
    from .models import Status

    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    text = response.text.strip()
    if text == found:
        return Status.FOUND, {}, None
    if text == missing:
        return Status.NOT_FOUND, {}, None
    return Status.UNKNOWN, {}, "No supported literal email-lookup result was returned."


def atlassian_lookup(data) -> tuple[bool | None, dict, str | None]:
    """Keep authentication routing separate from the retained account markers.

    Atlassian supports creating accounts at first SAML login. A redirect alone
    therefore does not establish an existing account. Returned route metadata
    is retained, with its scope stated explicitly.
    """
    unknown = "Unrecognised Atlassian response; account status is unknown."
    if not isinstance(data, dict) or has_service_error(data):
        return None, {}, unknown
    action = data.get("action")
    if action == "redirect":
        # The legacy auth_type key is redacted by Finding's credential rules.
        # Project only this fixed public label, without relaxing those rules.
        extra = {"auth_type": "Sign-in redirect", "sign_in_method": "Sign-in redirect",
                 "scope": "authentication routing"}
        route_type = data.get("redirect_type")
        if isinstance(route_type, str) and route_type.strip():
            extra["sso_type"] = route_type
        return None, extra, "Sign-in routing was returned; it does not establish an existing Atlassian account."
    # A route instruction conflicts with a plain signup/password action.
    if data.get("redirect_type") not in (None, "") or data.get("redirect_url") not in (None, ""):
        return None, {}, unknown
    if action == "signup":
        return False, {}, None
    if action == "no_action":
        return True, {"auth_type": "Password / Social", "sign_in_method": "Password / Social"}, None
    return None, {}, unknown


def wordpress_lookup(data) -> tuple[bool | None, dict, str | None]:
    """Parse WordPress.com's HTTP envelope, not just its outer HTTP 200.

    Retain the exact error pairs documented by user-scanner PR #529. Automattic's Calypso
    auth-options client also reads the passwordless flag from successful replies.
    Email verification and login options are not proof of identity/ownership.
    """
    unknown = "Unrecognised WordPress response; account status is unknown."
    if not isinstance(data, dict) or has_service_error(data):
        return None, {}, unknown
    code, body = data.get("code"), data.get("body")
    if type(code) is not int or not isinstance(body, dict):
        return None, {}, unknown
    markers = ("email_verified", "passwordless")
    error = body.get("error")
    # Only these exact status/error pairs are account evidence. Other error
    # fields or simultaneous success markers invalidate that interpretation.
    expected = (code == 403 and error == "email_login_not_allowed"
                or code == 404 and error == "unknown_user")
    if expected and not any(key in body for key in markers):
        remainder = {key: value for key, value in body.items() if key != "error"}
        if not has_service_error(remainder):
            if code == 403:
                return True, {"login_method": "username only"}, None
            return False, {}, None
    if code == 429:
        return None, {}, "Rate limited by WordPress (API status 429); account status is unknown."
    if code in (401, 403, 406, 407, 418, 451):
        return None, {}, f"WordPress access blocked (API status {code}); account status is unknown."
    if code != 200 or has_service_error(body):
        return None, {}, unknown
    extra = {key: body[key] for key in markers if key in body}
    if not extra or any(type(value) is not bool for value in extra.values()):
        return None, {}, unknown
    # A returned false verification flag describes an unverified address;
    # it is not the provider's unknown_user response.
    return True, extra, None
