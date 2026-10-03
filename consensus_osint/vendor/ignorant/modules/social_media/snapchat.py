"""Retained Snapchat validation parser; current provider behaviour is unverified."""
import random

import httpx

from consensus_osint.vendor.ignorant.localuseragent import ua
from consensus_osint.vendor.ignorant.response import (
    has_service_error, phone_parts, phone_result, read_response, set_exists,
)
import phonenumbers


async def snapchat(phone, country_code, client, out):
    name = "snapchat"
    domain = "snapchat.com"
    method = "register"
    result = phone_result(name, domain, method)
    out.append(result)
    number = phone_parts(phone, country_code)
    region = phonenumbers.region_code_for_number(number) if number is not None else None
    if region not in phonenumbers.SUPPORTED_REGIONS:
        result["reason"] = "A valid phone number with a supported geographic region is required; no lookup was submitted."
        return
    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'Origin': 'https://accounts.snapchat.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Sec-GPC': '1',
        'TE': 'Trailers',
    }
    response = await client.get("https://accounts.snapchat.com", headers=headers)
    if read_response(response, result, html=True) is None:
        return
    try:
        token = response.cookies.get("xsrf_token")
    except httpx.CookieConflict:
        token = None
    if not isinstance(token, str) or not token.strip():
        result["reason"] = "Required validation cookie was missing or ambiguous; no phone lookup was submitted."
        return
    data = {"phone_country_code": region,
            "phone_number": phonenumbers.national_significant_number(number), "xsrf_token": token}
    response = await client.post("https://accounts.snapchat.com/accounts/validate_phone_number", headers=headers, data=data)
    payload = read_response(response, result)
    if payload is None or has_service_error(payload):
        return
    if payload.get("status") not in (None, "ok") or payload.get("message") not in (None, ""):
        return
    status = payload.get("status_code")
    if status == "TAKEN_NUMBER":
        set_exists(result, True)
    elif status == "OK":
        set_exists(result, False)
