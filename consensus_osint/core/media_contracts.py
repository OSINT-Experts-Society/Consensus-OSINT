"""Retained media lookup evidence; no requests or claims of live reliability.

Only explicit, typed provider markers yield a verdict. Availability signals do
not establish ownership, and successful signup requests are not negative proof.
"""
from __future__ import annotations

import json

from .mailbox_contracts import http_issue, valid_token
from .models import Status
from .provider_contracts import has_service_error


def _failed(data):
    return (has_service_error(data)
            or type(data.get("status")) is int and data["status"] >= 400)


def lastfm_field(data, field="email"):
    if not isinstance(data, dict) or _failed(data):
        return None
    item = data.get(field)
    if not isinstance(item, dict) or _failed(item):
        return None
    valid, errors = item.get("valid"), item.get("error_messages", [])
    if type(valid) is not bool or not isinstance(errors, list):
        return None
    if valid is True and not errors:
        return False
    duplicate = ("Sorry, that email address is already registered to another account." if field == "email"
                 else "Sorry, this username isn't available.")
    if valid is False and errors == [duplicate]:
        return True
    return None


def rambler_profile(data, username, domain):
    """The login_available source records only a positive profile marker."""
    if not isinstance(data, dict) or _failed(data):
        return None
    result = data.get("result")
    if not isinstance(result, dict) or _failed(result):
        return None
    profile = result.get("profile")
    address = f"{username}@{domain}"
    if not isinstance(profile, dict) or _failed(profile) or profile.get("status") != "exist":
        return None
    if (result.get("email", address) == address and profile.get("email", address) == address
            and profile.get("username", username) == username and profile.get("realm", domain) == domain):
        return True
    return None


def json_verdict(site, data, query):
    if (isinstance(data, dict) and isinstance(data.get("email"), str)
            and data["email"].casefold() != query.casefold()):
        return None
    if site == "lastfm":
        return lastfm_field(data)
    if site == "tunefind":
        if not isinstance(data, dict) or _failed({k: v for k, v in data.items() if k != "errors"}):
            return None
        errors = data.get("errors")
        duplicate = "Someone is already registered with that email address"
        if (isinstance(errors, dict) and errors.get("email") in (duplicate, [duplicate])
                and data.get("success") is not True):
            return True
        return None
    if site == "spotify_v2":
        if not isinstance(data, dict):
            return None
        if data.get("error") == "already_exists" and "success" not in data:
            return True if not _failed({k: v for k, v in data.items() if k != "error"}) else None
        if data.get("success") is True and not _failed(data):
            return False
        return None
    if not isinstance(data, dict) or _failed(data):
        return None
    if site == "ello":
        availability = data.get("availability")
        if isinstance(availability, dict) and not _failed(availability) and type(availability.get("email")) is bool:
            return not availability["email"]
    elif site == "komoot":
        if data.get("type") in ("login", "register"):
            return data["type"] == "login"
    elif site == "rambler":
        result = data.get("result")
        if isinstance(result, dict) and not _failed(result):
            if isinstance(result.get("email"), str) and result["email"].casefold() != query.casefold():
                return None
            value = result.get("exists")
            if type(value) is int and value in (0, 1):
                return value == 1
    elif site == "smule":
        if type(data.get("email")) is bool:
            return data["email"]
    elif site == "soundcloud":
        if data.get("status") in ("available", "in_use"):
            return data["status"] == "in_use"
    elif site == "spotify":
        value = data.get("status")
        if type(value) is int and value in (1, 20):
            return value == 20
    return None


def outcome(site, response, query):
    status, reason = http_issue(response.status_code, response.headers, response.text)
    if status is not None:
        return status, {}, reason
    if site in ("sevencups", "blip"):
        from bs4 import BeautifulSoup

        page = BeautifulSoup(response.text, "html.parser")
        for item in page.select("script, style, template, noscript, [hidden], [aria-hidden=true]"):
            item.decompose()
        text = page.get_text(" ", strip=True)
        duplicate = ("Account already exists with this email address" if site == "sevencups"
                     else "That email address is already in use.")
        exists = True if duplicate in text else None
    else:
        try:
            exists = json_verdict(site, response.json(), query)
        except ValueError:
            return Status.UNKNOWN, {}, "Malformed provider JSON; account status is unknown."
    if exists is not None:
        return (Status.FOUND if exists else Status.NOT_FOUND), {}, None
    return Status.UNKNOWN, {}, "Unrecognised or conflicting lookup response; account status is unknown."


def meta_token(text, name):
    from html.parser import HTMLParser

    class Tokens(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.values, self.ignored = [], []

        def handle_starttag(self, tag, attrs):
            if tag in ("script", "style", "template", "noscript"):
                self.ignored.append(tag)
            if not self.ignored and tag == "meta" and ("name", name) in attrs:
                data = dict(attrs)
                self.values.append(data.get("content") if len(data) == len(attrs) else None)

        def handle_endtag(self, tag):
            if self.ignored and self.ignored[-1] == tag:
                self.ignored.pop()

    page = Tokens()
    page.feed(text)
    values = page.values
    return values[0] if len(values) == 1 and valid_token(values[0]) else None


def soundcloud_client(text):
    """Find the retained inline JSON configuration independently of script order."""
    from bs4 import BeautifulSoup

    values = []
    for script in BeautifulSoup(text, "html.parser").find_all("script"):
        if (script.has_attr("src") or script.find_parent(["template", "noscript"])
                or script.get("type", "").lower() not in ("", "application/json", "text/javascript")):
            continue
        try:
            data = json.loads(script.get_text())
        except ValueError:
            continue
        config = data.get("runtimeConfig") if isinstance(data, dict) else None
        if isinstance(config, dict) and "clientId" in config:
            values.append(config["clientId"])
    return values[0] if len(values) == 1 and valid_token(values[0]) else None
