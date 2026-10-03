"""Existing Eventbrite sign-in prerequisite and read-only email lookup contract."""
from __future__ import annotations

from .mailbox_contracts import http_issue, valid_token
from .models import Status
from .provider_contracts import email_flag_outcome

ENDPOINT = "https://www.eventbrite.com/api/v3/users/lookup/"
RULE_HEADERS = {"Cookie": "csrftoken={csrftoken_value}", "X-Csrftoken": "{csrftoken_value}",
                "Referer": "https://www.eventbrite.com/", "Content-Type": "application/json"}
RULE_PAYLOAD = '{"email":"{email}","source_user_id":"","source_provider":""}'
RULE_DETECT = {"type": "message", "found_status": [], "found_strings": ['"exists":true'],
               "missing_status": [404], "missing_strings": ['"exists":false'],
               "json_found_path": [], "json_missing_path": []}
RULE_EXTRACT = [{"name": "User ID", "schema": "JSON", "path": ["user_id"], "prefix": None, "item_path": None}]


def shipped_rule(entry):
    return (entry.get("id") == "eventbrite" and entry.get("kind") == "email" and entry.get("source") == "consensus"
            and entry.get("method") == "POST" and entry.get("url") == "https://eventbrite.com"
            and entry.get("check_url") == ENDPOINT and entry.get("headers") == RULE_HEADERS
            and entry.get("payload") == RULE_PAYLOAD and entry.get("detect") == RULE_DETECT
            and entry.get("extract") == RULE_EXTRACT and not entry.get("form") and not entry.get("impersonate")
            and entry.get("follow_redirects", True) in (None, True))


def csrf_token(cookies):
    """Never borrow a similarly named cookie from another scanned provider."""
    values = []
    for cookie in cookies.jar:
        if (cookie.name == "csrftoken" and cookie.domain.lstrip(".").lower() in {"eventbrite.com", "www.eventbrite.com"}
                and cookie.path == "/" and not cookie.is_expired()):
            values.append(cookie.value)
    if not values or len(set(values)) != 1:
        return None
    token = values[0]
    return token if valid_token(token) and token.isascii() and not any(c in token for c in ';,"\\') else None


async def lookup(request, email, headers, *, signin_url="https://www.eventbrite.com/signin/", cookie_source=None,
                 payload_extra=None):
    """The callback returns HTTPX responses while retaining its existing route/session."""
    try:
        response = await request("GET", signin_url, headers=headers)
        status, reason = http_issue(response.status_code, response.headers, response.text)
        if status is not None:
            return status, {}, reason, response.status_code
        # A caller-owned jar retains cookies set during followed redirects.
        token = csrf_token(cookie_source()) if cookie_source else None
        if token is None:
            token = csrf_token(response.cookies)
        if token is None:
            return Status.UNKNOWN, {}, "A valid Eventbrite CSRF cookie was not returned; no email lookup was submitted.", response.status_code
        lookup_headers = {key: value for key, value in headers.items() if key.lower() not in {"cookie", "x-csrftoken"}}
        lookup_headers.update({"Cookie": "csrftoken=" + token, "X-CSRFToken": token})
        response = await request("POST", ENDPOINT, headers=lookup_headers, json={**(payload_extra or {}), "email": email})
        status, fields, reason = email_flag_outcome(response, "exists", email)
        if status is Status.NOT_FOUND and response.json().get("user_id") not in (None, ""):
            return Status.UNKNOWN, {}, "A missing-account flag conflicts with a returned user ID", response.status_code
        if status is Status.FOUND:
            ident = response.json().get("user_id")
            if (type(ident) is int and ident > 0) or (isinstance(ident, str) and ident.strip()):
                fields = {"user_id": ident}  # Existing rule capability, preserved through native selection too.
        return status, fields, reason, response.status_code
    except Exception:
        return Status.ERROR, {}, "Eventbrite prerequisite or lookup request failed; account status is unknown.", None
