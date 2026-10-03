"""Developer-service validation messages are evidence only in coherent responses."""
import json
import re

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def _bound(data, email):
    return all(key not in data or isinstance(data[key], str) and data[key].casefold() == email.casefold()
               for key in ("email", "email_address"))


def outcome(response, site, email):
    accepted = (204, 422) if site == "envato" else (200,)
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=accepted)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No unambiguous, query-bound validation message was returned.")
    if site == "envato" and response.status_code == 204:
        return (Status.NOT_FOUND, {}, None) if not response.text.strip() else unknown
    text = response.text.strip()
    if site == "envato-legacy" and text == "Email is already in use":
        return Status.FOUND, {}, None
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = text if site == "huggingface" else None
    if site == "huggingface":
        error_message = False
        if isinstance(data, dict):
            fields = set(data) & {"message", "error"}
            if len(fields) != 1 or set(data) - {"message", "error", "email", "email_address"} or not _bound(data, email):
                return unknown
            field = next(iter(fields))
            error_message = field == "error"
            data = data[field]
        if not isinstance(data, str):
            return unknown
        if not error_message and data == "This email address is available.":
            return Status.NOT_FOUND, {}, None
        if re.fullmatch(r"(?:(?:this |the )?email(?: address)? )?already exists[.!]?", data, re.I):
            return Status.FOUND, {}, None
        return unknown
    if not isinstance(data, dict) or not _bound(data, email):
        return unknown
    if site in ("envato", "envato-legacy"):
        if has_service_error({key: value for key, value in data.items() if key != "error_message"}):
            return unknown
        message = data.get("error_message")
        if isinstance(message, str) and re.fullmatch(
                r"(?:(?:this |the )?email(?: address)? (?:is )?)?already in use[.!]?", message, re.I):
            return Status.FOUND, {}, None
    if site == "medium":
        if has_service_error(data):
            return unknown
        record = data.get("data")
        if not isinstance(record, dict) or has_service_error(record) or not _bound(record, email):
            return unknown
        result = record.get("sendAcctAuthEmail")
        if not isinstance(result, dict) or has_service_error(result) or not _bound(result, email):
            return unknown
        if result.get("__typename") == "NotFound" and result.get("message") == "User does not exist":
            return Status.NOT_FOUND, {}, None
        return Status.UNKNOWN, {}, "A login-mail acknowledgment does not establish account existence."
    return unknown
