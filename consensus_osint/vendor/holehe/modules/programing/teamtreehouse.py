from consensus_osint.core.email_validation import csrf_setup, duplicate_message
from consensus_osint.core.http import random_user_agent
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def teamtreehouse(email, client, out):
    name = "teamtreehouse"
    domain = "teamtreehouse.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        "User-Agent": random_user_agent(), "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en,en-US;q=0.5", "Referer": "https://teamtreehouse.com/subscribe/new?trial=yes",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest", "Origin": "https://teamtreehouse.com",
    }
    response = await client.get("https://teamtreehouse.com/subscribe/new?trial=yes", headers=headers)
    token, issue = csrf_setup(response, "teamtreehouse")
    if issue is not None:
        apply_mailbox_outcome(result, issue, http_status=response.status_code)
        return
    headers["X-CSRF-Token"] = token
    response = await client.post("https://teamtreehouse.com/account/email_address",
                                 headers=headers, data={"email": email}, follow_redirects=False)
    apply_mailbox_outcome(result, duplicate_message(response, "that email address is taken."),
                         http_status=response.status_code)
