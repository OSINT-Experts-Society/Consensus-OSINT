"""Typed evidence for exact shipped login/availability rules."""
import hashlib
import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error

_HASHES = {
    "linkedin": "c3a1ba8fa09bec58124b58c2aed6cc8983c5ae92b361d3cd4a86d3cdfee871ac",
    "zoom": "6acf47b547c1629e47ead5b500d95f961e2aaa25131c3294dd014a0a9d05e357",
    "sexvid-email": "c90acdc8622ea98192534bcea412a6f831933d84bfc0a63deba48f9f1c7ac7f4",
    "hanzii-email": "0cb4dccdd59c3b5c34e9e31ca7a7f704114d5900da5764f843882979cbbc4b71",
    "apple": "1a9b960580fa02984beb01cbc118b252e881fb26185fb09ac0898c36601b3467",
    "insightly-email": "b5d93d9dcb7c7201925ea866fbcef5705fb988cd68fe223d467b6996e0be2d43",
    "olx": "cbd63f2962f976aaec1ac7c3900edbab586618338e35215a93c9c3fae79bf89e",
    "gravatar": "78870e5498722a84477949d1f0d195514adda6b5a2020732f1d8c4ce763cb354",
    "picsart": "3d7bcb66247a567e2babbaf537991e8939f342264253588bfa491aaa48b3558a",
    "skype-microsoft": "904acdae5a5f39fd2ee1b5130f9abb34bb1234fa7334996f278fac68a3606a1e",
    "adobe": "99bdc4edc4b70b31ee0208410d3f65cb66762381d713f8ceefae7f177efdfd24",
    "notion": "a80b2394c163dc5955409604d95e5c46ec52c5b56c580ee1f570b10fa0974935",
    "netshoes": "d78f4506f9b50e1d07e0970b9a6302eb6fb939a00e833440eac8315677fad932",
}


def shipped_rule(entry):
    expected = _HASHES.get(entry.get("id"))
    if expected is None:
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == expected


def _coherent(data, query):
    return (isinstance(data, dict) and not has_service_error(data)
            and all(key not in data or isinstance(data[key], str) and data[key].casefold() == query.casefold()
                    for key in ("email", "username", "Username")))


def outcome(kind, code, text, query, headers):
    """Return a guarded verdict, or None where only a preflight is supported."""
    if kind == "hanzii-email" and code == 401:
        # The native implementation retains this exact legacy reset error.
        # A bare 401 or any successful/conflicting fields are not absence.
        issue, _ = http_issue(200, headers, text)
        try:
            data = json.loads(text, object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            data = None
        if (issue is None and isinstance(data, dict) and type(data.get("code")) is int
                and data["code"] == 401 and data.get("error") == "Email is not exist"
                and set(data) <= {"code", "error", "email"}
                and _coherent({key: value for key, value in data.items() if key != "error"}, query)):
            return Status.NOT_FOUND, {}, None
    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, {}, reason
    if kind == "zoom" and "invalid" in (text or "").casefold():
        # The legacy substring also matches rejected tokens, sessions, passwords
        # and malformed addresses. None establishes absence of an account.
        return Status.UNKNOWN, {}, "Zoom rejected input or the request; account existence is unverified"
    if kind in ("linkedin", "zoom"):
        # No successful account response schema is established for these rules.
        # This guard enforces transport status; the shared evaluator follows.
        return None
    unknown = (Status.UNKNOWN, {}, "No coherent typed login/availability response")
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown
    if kind in ("sexvid-email", "hanzii-email"):
        if not _coherent(data, query):
            return unknown
        acknowledged = data.get("status") == "success" if kind == "sexvid-email" else data.get("message") == "Success"
        if acknowledged:
            scope = "Reset request acknowledged; account existence and email delivery are unverified"
            return Status.UNKNOWN, {"scope": scope}, scope
        return unknown
    if kind == "insightly-email":
        from .crm_contracts import _json_verdict

        flag = _json_verdict("insightly", data)
        return unknown if flag is None else ((Status.FOUND if flag else Status.NOT_FOUND), {}, None)
    if kind == "apple":
        if not _coherent(data, query) or type(data.get("used")) is not bool:
            return unknown
        return (Status.FOUND if data["used"] else Status.NOT_FOUND), {}, None
    if kind == "olx":
        # Error precedence only: no successful OLX envelope has been verified.
        # A reply carrying neither recognised marker says nothing about the account.
        if not _coherent(data, query):
            return unknown
        if "EMAIL" not in text and "ACCOUNT_NOT_FOUND" not in text:
            return Status.UNKNOWN, {}, "Unrecognised OLX response; account existence is unverified"
        return None
    if kind == "gravatar":
        if not _coherent(data, query):
            return unknown
        entries = data.get("entry")
        if not isinstance(entries, list) or len(entries) != 1 or not _coherent(entries[0], query):
            return unknown
        entry = entries[0]
        email = query.strip().lower().encode("utf-8")
        hashes = {hashlib.sha256(email).hexdigest(), hashlib.md5(email, usedforsecurity=False).hexdigest()}
        digest = entry.get("hash")
        if not isinstance(digest, str) or digest.lower() not in hashes:
            return unknown
        fields = {"scope": "Gravatar public profile associated with the email hash; not proof of ownership or activity"}
        for source, label in (("displayName", "Name"), ("preferredUsername", "Username"), ("aboutMe", "About Me"),
                              ("currentLocation", "Location"), ("job_title", "Job"), ("company", "Company")):
            if value := _text(entry.get(source)):
                fields[label] = value
        raw = entry.get("thumbnailUrl")
        if isinstance(raw, str) and "\\" not in raw and (avatar := _url(raw)):
            fields["Avatar"] = avatar
        for source, label, key, urls in (("contactInfo", "Contact", "value", False), ("emails", "Emails", "value", False),
                                         ("accounts", "Accounts", "url", True), ("urls", "URLs", "value", True)):
            rows = entry.get(source)
            if not isinstance(rows, list):
                continue
            values = []
            for row in rows:
                raw = row.get(key) if isinstance(row, dict) else None
                value = _text(raw)
                if urls:
                    value = _url(raw) if value and "\\" not in raw else None
                if value and value not in values:
                    values.append(value)
            if values:
                fields[label] = values
        return Status.FOUND, fields, None
    if kind in ("picsart", "skype-microsoft"):
        if not _coherent(data, query):
            return unknown
        if kind == "skype-microsoft":
            throttle = data.get("ThrottleStatus", 0)
            if type(throttle) is not int or throttle < 0:
                return unknown
            if throttle:
                return Status.RATE_LIMITED, {}, "Microsoft sign-in discovery throttled"
            code = data.get("IfExistsResult")
            if type(code) is not int or code not in (0, 1, 5, 6):
                return unknown
            fields = {"scope": "Microsoft sign-in discovery; not proof of mailbox ownership", "if_exists_result": code}
            return (Status.NOT_FOUND if code == 1 else Status.FOUND), fields, None
        if data.get("status") != "success":
            return unknown
        response = data.get("response")
        flag = response if type(response) is bool else None
        if isinstance(response, dict):
            matches = [value for key, value in response.items() if key.casefold() == query.casefold()]
            if len(matches) == 1 and type(matches[0]) is bool:
                flag = matches[0]
        elif isinstance(response, list) and len(response) == 1:
            if type(response[0]) is bool:
                flag = response[0]
            elif isinstance(response[0], str) and response[0].casefold() == query.casefold():
                flag = True
        if flag is None:
            return unknown
        return (Status.FOUND if flag else Status.NOT_FOUND), {}, None
    if kind != "adobe":
        field = "hasAccount" if kind == "notion" else "exists"
        if not _coherent(data, query) or type(data.get(field)) is not bool:
            return unknown
        return (Status.FOUND if data[field] else Status.NOT_FOUND), {}, None
    if not isinstance(data, list):
        return unknown
    if not data:
        return Status.NOT_FOUND, {}, None
    for account in data:
        if not _coherent(account, query):
            return unknown
        methods = account.get("authenticationMethods")
        if not isinstance(methods, list) or not methods:
            return unknown
        if any(not isinstance(method, dict) or has_service_error(method) or not _text(method.get("id")) for method in methods):
            return unknown
    fields = {}
    if len(data) == 1 and isinstance(data[0].get("images"), dict):
        raw = data[0]["images"].get("230")
        if isinstance(raw, str) and "\\" not in raw and (avatar := _url(raw)):
            fields["Avatar"] = avatar
    return Status.FOUND, fields, None
