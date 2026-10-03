"""Inspect the existing sign-in step without guessing an account-negative page."""
import random

from bs4 import BeautifulSoup

from consensus_osint.vendor.holehe.localuseragent import ua


def _read_page(response, result):
    result["http_status"] = response.status_code
    if response.status_code != 200:
        result.update(rateLimit=response.status_code == 429,
                      blocked=response.status_code in (401, 403),
                      reason=f"Sign-in request returned HTTP {response.status_code}")
        return None
    body = BeautifulSoup(response.text, "html.parser")
    if body.select_one('#captchacharacters, input[name="cvf_captcha_input"], input[name="guess"]') or "robot check" in body.get_text(" ").lower():
        result.update(blocked=True, reason="Sign-in page requires a CAPTCHA")
        return None
    return body


async def amazon(email, client, out):
    name = "amazon"
    domain = "amazon.com"
    method = "login"
    result = dict(name=name, domain=domain, method=method, frequent_rate_limit=False,
                  rateLimit=False, exists=None, unknown=True,
                  reason="Unrecognised sign-in response; no validated account-absence signal")
    out.append(result)
    headers = {"User-Agent": random.choice(ua["browsers"]["chrome"])}
    url = 'https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3F_encoding%3DUTF8%26ref_%3Dnav_ya_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&'
    response = await client.get(url, headers=headers)
    body = _read_page(response, result)
    if body is None:
        return
    data = {item["name"]: item["value"] for item in body.select("form input")
            if "name" in item.attrs and "value" in item.attrs}
    if not data:
        result["reason"] = "Sign-in form state is missing; lookup was not submitted"
        return
    data["email"] = email
    response = await client.post("https://www.amazon.com/ap/signin/", data=data)
    body = _read_page(response, result)
    if body is not None and body.find("div", {"id": "auth-password-missing-alert"}):
        result.update(exists=True, unknown=False, reason=None)
