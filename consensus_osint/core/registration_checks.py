"""Validation-only endpoints adapted from User Scanner (MIT).

Requests do not submit signup, login, reminder or password-reset actions.
Response contracts are upstream evidence, not proof of live availability.
"""
from __future__ import annotations

import json
import re

import httpx

from ..vendor.user_scanner.core.helpers import get_global_timeout, get_proxy
from ..vendor.user_scanner.core.result import Result
from .email_validation import _unique_object
from .mailbox_contracts import http_issue

JOBS = {
    "dirbam": ("https://www.dirbam.lt", "/patikrinti/el-pastas", "Paskyra su tokių el.paštu jau yra"),
    "otsintood": ("https://www.otsintood.ee", "/kontrolli/e-post", "Selle e-postiga on juba kasutaja registreeritud"),
    "visidarbi": ("https://www.visidarbi.lv", "/parbaude/e-pasts", "Profils ar šādu e-pasta adresi jau ir reģistrēts"),
}
SITES = {name: values[0] for name, values in JOBS.items()}
SITES.update({"alza_" + country: "https://www.alza." + country for country in ("at", "cz", "de", "hu", "sk")})


def parse(provider, response, email=None):
    url = SITES[provider]
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None or response.status_code != 200:
        return Result.error(reason or "Unexpected validation status", url=url)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid validation JSON", url=url)
    if provider in JOBS:
        if data == JOBS[provider][2]:
            return Result.taken(url=url, extra={"scope": "Registration association; email ownership is unverified"})
        if data == "true":
            return Result.available(url=url)
    elif isinstance(data, dict):
        if (data.get("success") is False or data.get("ok") is False
                or data.get("status") in ("error", "failed", "fail")
                or email is not None and any(k in data and data[k] != email for k in ("email", "login"))):
            return Result.error("Conflicting validation evidence", url=url)
        state = data.get("LoginAvailabilityType")
        # bool is an int subclass; true must not become account type 1.
        if (type(state) is int and state in (0, 1, 2)
                and data.get("ErrorLevel") == 0 and type(data.get("ErrorLevel")) is int
                and data.get("ErrorNeoPurchaseFailed") is False
                and data.get("DevErrorMessage") is None and data.get("Message") is None
                and not data.get("error") and not data.get("errors")):
            if state == 1:
                return Result.taken(url=url, extra={"scope": "Registered account; email ownership is unverified"})
            if state == 2:
                return Result.available(url=url, reason="Guest order association; no registered account",
                                        extra={"guest_order_association": True})
            return Result.available(url=url)
    return Result.error("Email validation is inconclusive", url=url)


async def validate(provider, email):
    url = SITES[provider]
    if not isinstance(email, str) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return Result.error("One valid email address is required", url=url)
    try:
        async with httpx.AsyncClient(timeout=get_global_timeout() or 15.0, proxy=get_proxy(),
                                     follow_redirects=False) as client:
            if provider in JOBS:
                response = await client.get(url + JOBS[provider][1], params={"email": email})
            else:
                landing = await client.get(url)
                issue, reason = http_issue(landing.status_code, landing.headers, landing.text)
                if issue is not None or landing.status_code != 200:
                    return Result.error(reason or "Validation prerequisite failed", url=url)
                response = await client.post(url + "/Services/EShopService.svc/CheckLoginAvailability",
                                             headers={"Origin": url, "Referer": url, "Accept": "application/json"},
                                             json={"login": email})
            return parse(provider, response, email)
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return Result.error(exc, url=url)
