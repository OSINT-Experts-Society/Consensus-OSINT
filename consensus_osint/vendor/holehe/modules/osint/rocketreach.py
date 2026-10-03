from consensus_osint.core.http import random_user_agent
from consensus_osint.core.software_email_contracts import outcome, prerequisite
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def rocketreach(email, client, out):
    name = "rocketreach"
    domain = "rocketreach.co"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://rocketreach.co/signup',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://rocketreach.co/signup", headers=headers)
    fields, issue = prerequisite(name, response)
    if issue is not None:
        apply_mailbox_outcome(result, issue, http_status=response.status_code)
        return
    headers["x-csrftoken"] = fields["csrfmiddlewaretoken"]
    response = await client.get("https://rocketreach.co/v1/validateEmail",
                                params={"email_address": email}, headers=headers, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
