"""Account lookup evidence for retained learning providers."""
import json
import re

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(response, site, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No coherent email-bound account lookup response")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    def coherent(record):
        return isinstance(record, dict) and not has_service_error(record) and (
            "email" not in record or isinstance(record["email"], str) and record["email"].casefold() == email.casefold())
    if not coherent(data):
        return unknown
    if site == "aslbloom":
        flag = data.get("foundUser")
        if flag in ("YES", "NO"):
            return (Status.FOUND if flag == "YES" else Status.NOT_FOUND), {}, None
        return unknown
    if type(data.get("status")) is not int or data["status"] != 200 or data.get("reason") != "OK":
        return unknown
    record = data.get("data")
    if not coherent(record):
        return unknown
    identities = record.get("identities")
    if not isinstance(identities, list) or not identities or not all(coherent(item) for item in identities):
        return unknown
    emails = [item.get("identity_value") for item in identities if item.get("identity_type") == "EMAIL"]
    if not emails or not all(isinstance(value, str) and value.casefold() == email.casefold() for value in emails):
        return unknown
    extras = {}
    phones = [item.get("identity_value") for item in identities if item.get("identity_type") == "PHONE"]
    if len(phones) == 1 and isinstance(phones[0], str):
        value = phones[0]
        if re.fullmatch(r"[0-9*xX]{10}", value):
            extras["phone"] = "+91" + value
        elif re.fullmatch(r"\+[0-9*xX]{8,15}", value):
            extras["phone"] = value
    return Status.FOUND, extras, None
