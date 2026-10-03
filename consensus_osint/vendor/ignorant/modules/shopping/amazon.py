"""Retained Amazon phone sign-in parser, guarded by Consensus.

No negative contract is assumed from a missing password marker. The sign-in
flow may deliver an OTP; both Consensus variants require notification opt-in.
"""
import random

from consensus_osint.vendor.ignorant.localuseragent import ua
from consensus_osint.vendor.ignorant.response import phone_result, read_response, set_exists


async def amazon(phone, country_code, client, out):
    name = "amazon"
    domain = "amazon.com"
    method = "login"
    result = phone_result(name, domain, method)
    out.append(result)
    headers = {"User-agent": random.choice(ua["browsers"]["chrome"])}
    url = "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3F_encoding%3DUTF8%26ref_%3Dnav_ya_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&"
    response = await client.get(url, headers=headers)
    page = read_response(response, result, html=True)
    if page is None:
        return
    data = {node["name"]: node["value"] for node in page.select("form input")
            if node.get("name") and node.get("value")}
    if not data:
        result["reason"] = "Required sign-in form fields were missing; no phone lookup was submitted."
        return
    data["email"] = str(country_code) + str(phone)
    response = await client.post("https://www.amazon.com/ap/signin/", data=data)
    page = read_response(response, result, html=True)
    if page is not None and page.find("div", {"id": "auth-password-missing-alert"}):
        set_exists(result, True)
