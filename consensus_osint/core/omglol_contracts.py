"""Documented omg.lol public address information contract."""

import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No successful omg.lol response")
    request = data.get("request")
    if (not isinstance(request, dict) or has_service_error(request)
            or request.get("success") is not True or type(request.get("status_code")) is not int
            or request["status_code"] != 200):
        return Result.error("No successful omg.lol request envelope")
    item = data.get("response")
    if (not isinstance(item, dict) or has_service_error(item)
            or not isinstance(item.get("address"), str) or item["address"].casefold() != user.casefold()):
        return Result.error("Response does not identify the requested omg.lol address")
    expiration = item.get("expiration")
    if (not isinstance(expiration, dict) or has_service_error(expiration)
            or expiration.get("expired") is not False):
        return Result.error("Address is expired or current registration is unconfirmed")
    extra = {"address": item["address"], "expired": False}
    if message := _text(item.get("message")):
        extra["message"] = message
    for source, target in (("registration", "registration_date"), ("expiration", "expiration")):
        value = item.get(source)
        if isinstance(value, dict) and not has_service_error(value):
            if date := _text(value.get("iso_8601_time")):
                extra[target] = date
    verification = item.get("verification")
    if isinstance(verification, dict) and not has_service_error(verification) and type(verification.get("verified")) is bool:
        extra["verified"] = verification["verified"]
    return Result.taken(extra=extra)
