"""Explicit general-service lookup evidence, independent of transport."""

import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(response, site, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No coherent account lookup response")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if not isinstance(data, dict) or has_service_error(data):
        return unknown
    if any(
        key in data and (not isinstance(data[key], str) or data[key].casefold() != email.casefold())
        for key in ("email", "user_name", "user_number")
    ):
        return unknown
    if site == "dollarfix":
        if data.get("msg") in ("The user does not exist.", "用户不存在。", "用户不存在"):
            return Status.NOT_FOUND, {}, None
    elif site == "secondline":
        user, account = data.get("has_user"), data.get("has_account")
        if data.get("result") == "success" and user in ("yes", "no") and account in ("yes", "no"):
            return (Status.FOUND if "yes" in (user, account) else Status.NOT_FOUND), {}, None
    elif site == "start_me":
        exists = data.get("exists")
        if type(exists) is bool:
            return (
                (Status.FOUND if exists else Status.NOT_FOUND),
                ({"account_locked": True} if exists and data.get("locked") is True else {}),
                None,
            )
    elif site == "dropbox":
        exists, recovery, passkey = (data.get(key) for key in ("exists", "exists_as_recovery_email", "has_passkey"))
        if not all(type(flag) is bool for flag in (exists, recovery, passkey)):
            return unknown
        if exists and recovery or not exists and not recovery and passkey:
            return unknown
        if exists:
            return Status.FOUND, {"exists_as_recovery_email": False, "has_passkey": passkey}, None
        if recovery:
            return (
                Status.FOUND,
                {"exists_as_recovery_email": True, "scope": "Recovery email association; not a primary login address"},
                None,
            )
        return Status.NOT_FOUND, {}, None
    return unknown
