"""Selected validation-only email endpoints; no reset, reminder or registration action."""

from __future__ import annotations

import json
import re

import httpx
from bs4 import BeautifulSoup

from ..vendor.user_scanner.core.helpers import get_global_timeout, get_proxy
from ..vendor.user_scanner.core.result import Result
from .email_validation import _unique_object
from .mailbox_contracts import http_issue, valid_token

SITES = {
    "codepen": "https://codepen.io",
    "quora": "https://www.quora.com",
    "tindie": "https://www.tindie.com",
    "wisio": "https://www.wisio.com",
    "medal": "https://medal.tv",
}
QUORA_QUERY = "SignupEmailForm_validateEmail_Query"
QUORA_HASH = "1db80096407be846d5581fe1b42b12fd05e0b40a5d3095ed40a0b4bd28f49fe7"


def parse(provider, response, email=None):
    url = SITES[provider]
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason, url=url)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid email-validation JSON", url=url)
    found = None
    extra = {"scope": "Email registration validation; mailbox ownership is unverified"}
    if isinstance(data, dict) and (
        data.get("success") is False
        or data.get("ok") is False
        or data.get("status") in ("error", "failed", "fail")
        or email is not None
        and "email" in data
        and data["email"] != email
    ):
        return Result.error("Conflicting email-validation evidence", url=url)
    if provider == "wisio" and type(data) is bool:
        found = data
    elif isinstance(data, dict):
        if provider == "medal" and data.get("valid") is True and type(data.get("exists")) is bool:
            if not data.get("error") and not data.get("errors"):
                found = data["exists"]
        elif provider == "tindie":
            if data == {"valid": False, "errors": ["Email already registered!"]}:
                found = True
            elif data == {"valid": True, "errors": [], "message": "Email available!"}:
                found = False
        elif provider == "codepen" and data.get("success") is True and not data.get("error") and not data.get("errors"):
            payload = data.get("payload")
            errors = payload.get("errors") if isinstance(payload, dict) and not payload.get("error") else None
            if isinstance(errors, dict) and set(errors) == {"email"}:
                if errors["email"] == ["That Email is already taken. Please choose another!"]:
                    found = True
                elif errors["email"] == []:
                    found = False
        elif provider == "quora" and not data.get("errors") and not data.get("error"):
            body = data.get("data")
            state = body.get("validateEmail") if isinstance(body, dict) else None
            if state in ("IN_USE", "NOT_CONFIRMED"):
                found = True
                extra["email_confirmed"] = state == "IN_USE"
                if state == "NOT_CONFIRMED":
                    extra["scope"] = "Unconfirmed registration association; does not confirm email ownership"
            elif state == "OK":
                found = False
    if found is True:
        return Result.taken(url=url, extra=extra)
    if found is False:
        return Result.available(url=url)
    return Result.error("Email validation is inconclusive", url=url)


async def validate(provider, email):
    show_url = SITES[provider]
    if not isinstance(email, str) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return Result.error("One valid email address is required", url=show_url)
    try:
        # A fresh client keeps the prerequisite cookie/token pair scoped to this
        # lookup. The adapter also applies the active scan's proxy and timeout.
        async with httpx.AsyncClient(
            timeout=get_global_timeout() or 15.0, proxy=get_proxy(), follow_redirects=False
        ) as client:
            if provider == "wisio":
                response = await client.get(
                    "https://be-lb-app.scaleabout.com/api/v1/auth/email/is_registered", params={"email": email}
                )
            elif provider == "medal":
                response = await client.post(show_url + "/api/users/email", json={"email": email})
            else:
                landing_url = {
                    "codepen": show_url + "/accounts/signup/user/free",
                    "tindie": show_url + "/accounts/signup/",
                    "quora": show_url,
                }[provider]
                landing = await client.get(landing_url)
                issue, reason = http_issue(landing.status_code, landing.headers, landing.text)
                if issue is not None:
                    return Result.error(reason, url=show_url)
                if provider == "codepen":
                    page = BeautifulSoup(landing.text, "html.parser")
                    for node in page.select("template, script, style"):
                        node.decompose()
                    tokens = [n.get("content") for n in page.select('meta[name="csrf-token"]')]
                    if len(tokens) != 1 or not valid_token(tokens[0]):
                        return Result.error("No unambiguous CodePen CSRF token", url=show_url)
                    response = await client.post(
                        show_url + "/accounts/duplicate_check",
                        headers={"x-csrf-token": tokens[0]},
                        data={"attribute": "email", "value": email, "context": "user"},
                    )
                elif provider == "tindie":
                    tokens = [
                        c.value
                        for c in client.cookies.jar
                        if c.name == "csrftoken" and c.domain.lstrip(".") in {"tindie.com", "www.tindie.com"}
                    ]
                    if len(tokens) != 1 or not valid_token(tokens[0]):
                        return Result.error("No unambiguous Tindie CSRF cookie", url=show_url)
                    response = await client.post(
                        show_url + "/accounts/check_email/",
                        data={"email": email},
                        headers={"Referer": landing_url, "X-CSRFToken": tokens[0]},
                    )
                else:
                    text = re.sub(r"<!--.*?-->", "", landing.text, flags=re.S)
                    tokens = re.findall(r'"formkey":\s*"([a-f0-9]+)"', text)
                    if len(set(tokens)) != 1:
                        return Result.error("No unambiguous Quora form key", url=show_url)
                    response = await client.post(
                        show_url + "/graphql/gql_para_POST",
                        params={"q": QUORA_QUERY},
                        headers={"quora-formkey": tokens[0]},
                        json={
                            "queryName": QUORA_QUERY,
                            "variables": {"email": email},
                            "extensions": {"hash": QUORA_HASH},
                        },
                    )
            return parse(provider, response, email)
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return Result.error(exc, url=show_url)
