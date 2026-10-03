"""Retained blip flow; offline parser repairs do not change execution policy."""
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.media_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def blip(email, client, out):
    name = "blip"
    domain = "blip.fm"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "Accept": "application/json, text/html;q=0.9"}
    try:
        headers.update(Origin="https://blip.fm", Referer="https://blip.fm/")
        response = await client.post("https://blip.fm/signup/save", headers=headers,
            data={"referringUrl": "", "genpass": "1", "signup[urlName]": "test", "signup[emailAddress]": email,
                  "g-recaptcha-response": "", "tos": "0"})
        apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Provider request or prerequisite failed; account status is unknown."))
