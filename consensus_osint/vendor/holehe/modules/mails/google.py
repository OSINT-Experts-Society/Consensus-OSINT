"""Legacy Google signup validation; current account existence is unverified."""
import json

from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import google_availability, google_token, http_issue
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def google(email, client, out):
    name = "google"
    domain = "google.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "X-Same-Domain": "1", "Google-Accounts-XSRF": "1",
               "Content-Type": "application/x-www-form-urlencoded;charset=utf-8", "Origin": "https://accounts.google.com",
               "Accept": "*/*", "Accept-Language": "en,en-US;q=0.5", "DNT": "1", "Connection": "keep-alive",
               "Referer": "https://accounts.google.com/signup/v2/webcreateaccount?continue=https%3A%2F%2Faccounts.google.com%2F&gmb=exp&biz=false&flowName=GlifWebSignIn&flowEntry=SignUp",
               "TE": "Trailers"}
    try:
        page = await client.get(
            "https://accounts.google.com/signup/v2/webcreateaccount?continue=https%3A%2F%2Faccounts.google.com%2FManageAccount%3Fnc%3D1&gmb=exp&biz=false&flowName=GlifWebSignIn&flowEntry=SignUp",
            headers=headers)
        status, reason = http_issue(page.status_code, page.headers, page.text)
        if status is not None:
            apply_mailbox_outcome(result, (status, {}, reason), http_status=page.status_code)
            return
        token = google_token(page.text)
        if token is None:
            result["reason"] = "Google's legacy signup prerequisite was not recognised; account status is unknown."
            result["http_status"] = page.status_code
            return
        response = await client.post(
            "https://accounts.google.com/_/signup/webusernameavailability", headers=headers,
            params={"hl": "fr", "rt": "j"}, data={
                "continue": "https://accounts.google.com/", "dsh": "", "hl": "fr",
                "f.req": json.dumps([token, "", "", email, False], ensure_ascii=False),
                "azt": "", "cookiesDisabled": "false",
                "deviceinfo": '[null,null,null,[],null,"FR",null,null,[],"GlifWebSignIn",null,[null,null,[],null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[],null,null,null,[],[]],null,null,null,null,0,null,false]',
                "gmscoreversion": "unined", "": ""})
        status, reason = http_issue(response.status_code, response.headers, response.text)
        outcome = (status, {}, reason) if status is not None else google_availability(response.text)
        apply_mailbox_outcome(result, outcome, http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Google lookup request failed; account status is unknown."))
