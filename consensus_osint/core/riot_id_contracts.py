"""Conservative verdicts from the third-party Riot ID lookup service."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data) or type(data.get("isTaken")) is not bool:
        return Result.error("No coherent Riot ID lookup verdict")
    if "riotId" in data and (not isinstance(data["riotId"], str) or data["riotId"].casefold() != user.casefold()):
        return Result.error("Lookup response names another Riot ID")
    extra = {"riot_id": user, "scope": "Third-party riotid-lookup.com availability report; not an official Riot account verification"}
    return Result.taken(extra=extra) if data["isTaken"] else Result.available(extra=extra)
