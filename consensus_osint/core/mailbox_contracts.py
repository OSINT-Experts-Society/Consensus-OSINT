"""Mailbox-provider response evidence, independent of transport and live reliability.

Signup availability, reserved identifiers, redirects and invalid input do not
establish current account ownership. Legacy markers retain their limited scope.
"""
from __future__ import annotations

import json
import re
from html import unescape
from html.parser import HTMLParser

from .errors import detect_error_page
from .models import Status
from .provider_contracts import has_service_error


def http_issue(status, headers, text, *, error=None, accepted=(200,)):
    if error is not None or not status:
        return Status.ERROR, "Provider request failed; account status is unknown."
    if status == 429:
        return Status.RATE_LIMITED, "Provider rate limited the request (HTTP 429); account status is unknown."
    if headers.get("cf-mitigated", "").lower() == "challenge":
        return Status.BLOCKED, "Provider challenge; account status is unknown."
    if status in (401, 403, 406, 407, 418, 451):
        return Status.BLOCKED, f"Provider access blocked (HTTP {status}); account status is unknown."
    if status not in accepted:
        return (Status.ERROR if status >= 500 else Status.UNKNOWN), f"Provider returned HTTP {status}; account status is unknown."
    problem = detect_error_page(text or "", status)
    if problem is not None:
        return Status.BLOCKED, "Provider returned a challenge or error page; account status is unknown."
    return None, None


def valid_token(value):
    return isinstance(value, str) and 0 < len(value) <= 4096 and not any(ord(c) <= 32 or ord(c) == 127 for c in value)


class _HiddenInputs(HTMLParser):
    def __init__(self, names):
        super().__init__(convert_charrefs=True)
        self.values = {name: [] for name in names}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        name = values.get("name")
        if tag == "input" and name in self.values:
            # Duplicate attributes or multiple matching inputs are ambiguous.
            if len(attrs) != len(values) or values.get("type", "").lower() != "hidden":
                self.values[name].append(None)
            else:
                self.values[name].append(values.get("value"))


def hidden_fields(text, names):
    page = _HiddenInputs(names)
    page.feed(text)
    if any(len(values) != 1 or not valid_token(values[0]) for values in page.values.values()):
        return None
    return {name: values[0] for name, values in page.values.items()}


def google_token(text):
    # Retain the legacy escaped-configuration token shape, but require one
    # complete, unambiguous value. Current signup pages may no longer have it.
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    values = re.findall(r'quot;,null,null,null,&quot;((?:(?!&quot;).){1,4096})&quot;', text)
    if len(values) != 1:
        return None
    value = unescape(values[0])
    return value if valid_token(value) else None


def google_availability(text):
    unknown = "The legacy Google signup response does not verify a current account or mailbox."
    try:
        data = json.loads(text.removeprefix(")]}'").strip())
    except ValueError:
        return Status.UNKNOWN, {}, unknown
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], list):
        data = data[0]
    if (isinstance(data, list) and len(data) == 2 and data[0] == "gf.wuar"
            and type(data[1]) is int and data[1] in (1, 2)):
        return Status.UNKNOWN, {"legacy_response_code": data[1], "scope": "Google signup validation"}, unknown
    return Status.UNKNOWN, {}, unknown


def yahoo_login(data):
    unknown = "The retained Yahoo sign-in response has no verified account-existence contract."
    if not isinstance(data, dict):
        return Status.UNKNOWN, {}, unknown
    render = data.get("render")
    if (isinstance(render, dict) and render.get("error") == "messages.ERROR_INVALID_USERNAME"
            and not has_service_error({key: value for key, value in data.items() if key != "render"})):
        return Status.UNKNOWN, {"provider_code": "messages.ERROR_INVALID_USERNAME"}, "Yahoo rejected the identifier; invalid input is not proof of account absence."
    if isinstance(data.get("location"), str) and data["location"]:
        return Status.UNKNOWN, {}, "Yahoo returned a sign-in redirect; its destination does not verify account existence."
    return Status.UNKNOWN, {}, unknown


def yahoo_signup(data, query, *, field="userId"):
    """Read the exact identifier field, never a fixed errors-list position."""
    unknown = (Status.UNKNOWN, {}, "No supported Yahoo account marker was returned.")
    if not isinstance(data, dict):
        return unknown
    if field in data and not _bound(data[field], query):
        return unknown
    if "status" in data and not (type(data["status"]) is int and data["status"] == 200
                                 or isinstance(data["status"], str) and data["status"] in ("ok", "success")):
        return unknown
    codes = []
    if field == "yid":
        errors = data.get("errors")
        if not isinstance(errors, list) or has_service_error({k: v for k, v in data.items() if k != "errors"}):
            return unknown
        for error in errors:
            if not isinstance(error, dict) or error.get("name") != field or not isinstance(error.get("error"), str):
                return unknown
            if (has_service_error({k: v for k, v in error.items() if k != "error"})
                    or "value" in error and not _bound(error["value"], query)):
                return unknown
            codes.append(error["error"])
    else:
        if has_service_error(data) or not isinstance(data.get("fields"), dict):
            return unknown
        fields = data["fields"]
        if set(fields) != {field} or not isinstance(fields[field], dict):
            return unknown
        value = fields[field]
        if "value" in value and not _bound(value["value"], query):
            return unknown
        error = value.get("error")
        if (not isinstance(error, dict) or not isinstance(error.get("id"), str)
                or has_service_error({k: v for k, v in value.items() if k != "error"})
                or has_service_error(error)):
            return unknown
        codes.append(error["id"])
    if len(codes) != 1:
        return unknown
    code = codes[0]
    if code == "IDENTIFIER_EXISTS":
        return Status.FOUND, {"provider_code": code}, None
    if code in ("IDENTIFIER_NOT_AVAILABLE", "RESERVED_WORD_PRESENT", "DANGLING_IDENTIFIER_EXISTS"):
        return Status.UNKNOWN, {"provider_code": code}, "Yahoo signup availability does not establish a current mailbox; reserved or deleted identifiers may be unavailable."
    return unknown


def _bound(value, query):
    return isinstance(value, str) and value.strip().casefold() == query.strip().casefold()


def _hint(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 320 and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def mailru(data, query, *, recovery=False):
    unknown = (Status.UNKNOWN, {}, "Missing, failed or unbound Mail.ru response; account status is unknown.")
    if not isinstance(data, dict) or has_service_error(data):
        return unknown
    # Retained existence replies may omit status. When present it must be the
    # typed success code; the recovery envelope always requires that code.
    code, body = data.get("status", None if recovery else 200), data.get("body")
    if type(code) is not int:
        return unknown
    if code == 429:
        return Status.RATE_LIMITED, {}, "Mail.ru API rate limit; account status is unknown."
    if code in (401, 403, 407):
        return Status.BLOCKED, {}, "Mail.ru API access denied; account status is unknown."
    if code != 200 or not isinstance(body, dict) or has_service_error(body):
        return unknown
    for record in (data, body):
        if "email" in record:
            value = record["email"]
            if record is body and isinstance(value, dict):
                # The existence API can return validation details in body.email.
                if has_service_error(value):
                    return unknown
            elif not _bound(value, query):
                return unknown
    if recovery:
        extra = {}
        if "exists" in body and body["exists"] is not True:
            return unknown
        for source, target in (("phones", "phone_hint"), ("emails", "recovery_email")):
            values = body.get(source, [])
            if not isinstance(values, list) or not all(_hint(value) for value in values):
                return unknown
            if values:
                extra[target] = ", ".join(value.strip() for value in values)
        if extra:
            return Status.FOUND, extra, None
        return unknown
    if type(body.get("exists")) is not bool:
        return unknown
    extra = {}
    alternatives = body.get("alternatives")
    if isinstance(alternatives, list) and alternatives and all(_hint(value) for value in alternatives):
        extra["alternatives"] = alternatives[:5]
    return (Status.FOUND if body["exists"] else Status.NOT_FOUND), extra, None
