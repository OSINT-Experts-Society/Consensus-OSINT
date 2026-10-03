"""Prerequisites and explicit duplicate messages for retained email validation.

Offline response contracts are not proof of current provider availability.
"""
import json

from bs4 import BeautifulSoup

from .mailbox_contracts import http_issue, valid_token
from .models import Status


def csrf_setup(response, provider):
    status, reason = http_issue(response.status_code, response.headers, response.text)
    if status is not None:
        return None, (status, {}, reason)
    soup = BeautifulSoup(response.text, "html.parser")
    tokens = [tag.get("content") for tag in soup.find_all("meta", attrs={"name": "csrf-token"})
              if not tag.find_parent(["template", "noscript"])]
    if len(tokens) != 1 or not valid_token(tokens[0]):
        return None, (Status.UNKNOWN, {}, f"{provider} lookup prerequisite is missing or ambiguous; no email was submitted.")
    return tokens[0], None


def _unique_object(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("Duplicate response field")
        data[key] = value
    return data


def duplicate_message(response, message):
    status, reason = http_issue(response.status_code, response.headers, response.text)
    if status is not None:
        return status, {}, reason
    unknown = (Status.UNKNOWN, {}, "No unambiguous duplicate-email message; account status is unknown.")
    body = response.text.strip()
    try:
        data = json.loads(body, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = body
    if isinstance(data, dict) and set(data) == {"error"}:
        data = data["error"]
    # Whole explicit messages only. Script/example fragments and successful
    # submissions do not establish presence or absence of an existing account.
    if isinstance(data, str) and data == message:
        return Status.FOUND, {}, None
    return unknown
