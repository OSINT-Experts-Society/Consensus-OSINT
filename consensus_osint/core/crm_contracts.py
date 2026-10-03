"""Retained CRM lookup contracts shared by the two vendor families.

These parsers make no requests and do not establish live provider reliability.
Unknown responses are not account absence; signup progress is not account proof.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urljoin, urlsplit

from .models import Status
from .provider_contracts import has_service_error


def http_problem(response, accepted=(200,), *, html=False) -> tuple[Status | None, str | None]:
    if response.status_code == 429:
        return Status.RATE_LIMITED, "Provider rate limited the request (HTTP 429); account status is unknown."
    if response.headers.get("cf-mitigated", "").lower() == "challenge":
        return Status.BLOCKED, "Provider challenge; account status is unknown."
    if response.status_code in (401, 403, 406, 407, 418, 451):
        return Status.BLOCKED, f"Provider access blocked (HTTP {response.status_code}); account status is unknown."
    if response.status_code not in accepted:
        return Status.UNKNOWN, f"Lookup request returned HTTP {response.status_code}; account status is unknown."
    if html:
        from bs4 import BeautifulSoup

        page = BeautifulSoup(response.text, "html.parser")
        if (page.select_one('#captchacharacters, input[name="guess"], input[name="cvf_captcha_input"]')
                or "robot check" in page.get_text(" ", strip=True).lower()):
            return Status.BLOCKED, "Provider CAPTCHA; account status is unknown."
    return None, None


def _axonaut(response, email):
    if response.status_code != 302:
        return None
    location = response.headers.get("location", "")
    if not location or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in location):
        return None
    try:
        target = urlsplit(urljoin("https://axonaut.com/onboarding/", location))
        if (target.scheme != "https" or target.hostname != "axonaut.com" or target.port not in (None, 443)
                or target.username is not None or target.password is not None or target.fragment or target.path != "/login"):
            return None
        if parse_qs(target.query, max_num_fields=20).get("email") == [email]:
            return True
    except ValueError:
        pass
    return None


def _nutshell(response):
    from bs4 import BeautifulSoup

    page = BeautifulSoup(response.text, "html.parser")
    for item in page.select("script, style, noscript, template, [hidden], [aria-hidden=true]"):
        item.decompose()
    text = page.get_text(" ", strip=True)
    yes = "Sorry, your password is incorrect" in text
    no = "find a Nutshell account for that email address." in text
    return yes if yes != no else None


def _json_verdict(site, data):
    if site in ("insightly", "nimble"):
        if data is True:
            return False
        if isinstance(data, str):
            if site == "insightly" and data.startswith("An account exists for this address. Use another address or"):
                return True
            if site == "nimble" and data == "I thought you looked familiar! This email is already registered.":
                return True
        return None
    if not isinstance(data, dict):
        return None
    if site == "pipedrive":
        errors = data.get("errors")
        remainder = {key: value for key, value in data.items() if key != "errors"}
        if has_service_error(remainder) or data.get("data") is not None:
            return None
        if isinstance(errors, dict) and set(errors) == {"user_email"}:
            if errors["user_email"] in ("Email is not available", ["Email is not available"]):
                return True
        return None
    if has_service_error(data):
        return None
    if site == "hubspot":
        if data.get("status") in ("INVALID_USER", "INVALID_PASSWORD"):
            return data["status"] == "INVALID_PASSWORD"
    elif site == "nocrm":
        account, url = data.get("account"), data.get("url")
        if type(account) is int and account == 1 and isinstance(url, str) and url.strip():
            return True
        if type(account) is int and account == 0 and url in (None, ""):
            return False
    elif site == "teamleader":
        if type(data.get("available")) is bool:
            return not data["available"]
    elif site == "zoho":
        # A generic 400 can mean invalid input or another failure. A data-centre
        # routing message with an unsupported status is also inconclusive.
        if type(data.get("status_code")) is int and data["status_code"] == 201 and data.get("message") == "User exists":
            return True
    return None


def crm_outcome(site, response, email) -> tuple[Status, str | None]:
    accepted = {"aboutme": (200, 409), "axonaut": (200, 302), "hubspot": (400,)}.get(site, (200,))
    status, reason = http_problem(response, accepted, html=site == "nutshell")
    if status is not None:
        return status, reason
    if site == "aboutme":
        return Status.UNKNOWN, "Signup success or an HTTP conflict alone does not establish whether this email was already registered."
    if site == "axonaut":
        exists = _axonaut(response, email)
    elif site == "nutshell":
        exists = _nutshell(response)
    else:
        try:
            data = response.json()
        except ValueError:
            return Status.UNKNOWN, "Malformed provider JSON; account status is unknown."
        exists = _json_verdict(site, data)
    if exists is not None:
        return (Status.FOUND if exists else Status.NOT_FOUND), None
    return Status.UNKNOWN, "Unrecognised or conflicting lookup response; account status is unknown."
