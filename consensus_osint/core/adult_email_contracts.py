"""Retained duplicate-email markers, not live provider availability claims."""
import json
from html.parser import HTMLParser

from .email_validation import _unique_object
from .mailbox_contracts import http_issue, valid_token
from .models import Status
from .provider_contracts import has_service_error


class _TokenInput(HTMLParser):
    def __init__(self, attribute):
        super().__init__(convert_charrefs=True)
        self.attribute = attribute
        self.tokens = []
        self.inert = []

    def handle_starttag(self, tag, attrs):
        if tag in ("template", "noscript", "script", "style"):
            self.inert.append(tag)
        if self.inert or tag != "input":
            return
        values = dict(attrs)
        if values.get(self.attribute) == "token":
            self.tokens.append(values.get("value") if len(values) == len(attrs) else None)

    def handle_endtag(self, tag):
        if tag in self.inert:
            self.inert = self.inert[:self.inert.index(tag)]


def prerequisite(response, site):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return None, (issue, {}, reason)
    parser = _TokenInput("name" if site == "pornhub" else "id")
    parser.feed(response.text)
    if len(parser.tokens) != 1 or not valid_token(parser.tokens[0]):
        return None, (Status.UNKNOWN, {}, "Missing or ambiguous lookup token; no email was submitted.")
    return parser.tokens[0], None


def outcome(response, site, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    duplicate = "Email has been taken."
    unknown = (Status.UNKNOWN, {}, "No unambiguous duplicate-email marker; account absence is not established.")
    if site == "redtube" and response.text.strip() == duplicate:
        return Status.FOUND, {}, None
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict) or data.get("error_message") != duplicate:
        return unknown
    if has_service_error({key: value for key, value in data.items() if key != "error_message"}):
        return unknown
    if "email_address" in data and (not isinstance(data["email_address"], str)
                                    or data["email_address"].casefold() != email.casefold()):
        return unknown
    # In this provider family `email` is an operation status, not an echo of the
    # address. A simultaneous validation-success marker conflicts with duplicate.
    if data.get("email") == "create_account_passed":
        return unknown
    return Status.FOUND, {}, None



def user_scanner_outcome(response, site, email):
    accepted = (200, 404) if site == "babestation" else (200,)
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=accepted)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No supported, query-bound email validation result was returned.")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict):
        return unknown
    if "email" in data and (not isinstance(data["email"], str) or data["email"].casefold() != email.casefold()):
        return unknown
    if site == "babestation":
        other = {key: value for key, value in data.items() if key not in ("success", "errors")}
        if not has_service_error(other) and data.get("success") is False and data.get("errors") == ["Email not found"]:
            return Status.NOT_FOUND, {}, None
        return Status.UNKNOWN, {}, "A reminder acknowledgment does not establish account existence."
    if site == "fantasia":
        if not has_service_error(data) and data.get("code") == "304" and data.get("message") == "User does not exist":
            return Status.NOT_FOUND, {}, None
        return Status.UNKNOWN, {}, "An authentication-code acknowledgment does not establish account existence."
    other = {key: value for key, value in data.items() if key != "error"}
    if has_service_error(other):
        return unknown
    if site == "faproulette":
        success = data.get("success")
        if type(success) is int and success == 1 and not has_service_error(data):
            return Status.NOT_FOUND, {}, None
        if data.get("error") == "already in use" and ("success" not in data or type(success) is int and success == 0):
            return Status.FOUND, {}, None
    if site == "superporn":
        if data.get("error") is True and data.get("message") == "Email is in use" and data.get("result") in (None, ""):
            return Status.FOUND, {}, None
        if data.get("error") is False and data.get("result") == "ok" and not data.get("message"):
            return Status.NOT_FOUND, {}, None
    return unknown
