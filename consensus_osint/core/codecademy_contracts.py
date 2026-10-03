'Parse Codecademy email validation responses conservatively.'
import json

from .email_validation import csrf_setup
from .mailbox_contracts import http_issue
from .models import Status


def setup(response):
    return csrf_setup(response, "Codecademy")


def _unique_object(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("Duplicate response field")
        data[key] = value
    return data


def outcome(response):
    status, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 400))
    if status is not None:
        return status, {}, reason
    unknown = (Status.UNKNOWN, {}, "Codecademy response does not establish the queried email's account status.")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    # Never search arbitrary fields for a duplicate phrase: it can refer to a
    # username. Conflicting errors and unexpected envelopes are inconclusive.
    if response.status_code != 400 or not isinstance(data, dict) or set(data) != {"errors"}:
        return unknown
    errors = data["errors"]
    if not isinstance(errors, dict) or set(errors) != {"email"}:
        return unknown
    messages = errors["email"]
    if (isinstance(messages, list) and len(messages) == 1
            and isinstance(messages[0], str)
            and messages[0] in ("is already taken", "has already been taken")):
        return Status.FOUND, {}, None
    return unknown
