"""Response preflight for the retained Zhihu publications rule."""
import hashlib
import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def shipped_rule(entry):
    if entry.get("id") != "zhihu":
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == "57c7326a7835b8e2b66f2fbe4de4da2ede1bacb7a51b5e03529772551ea4ac5e"


def preflight(code, text, headers):
    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, reason
    unknown = Status.UNKNOWN, "No coherent Zhihu API response"
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict) or has_service_error(data):
        return unknown
    # The successful publications schema and account-absence error are still
    # unverified. This preflight does not certify the remaining legacy marker;
    # it only refuses a marker that is a text value rather than a field name.
    if "is_start" in text and not _has_key(data, "is_start"):
        return Status.UNKNOWN, "The Zhihu paging field appears only as text; no reliable profile evidence"
    return None


def _has_key(value, name):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if name in item:
                return True
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False
