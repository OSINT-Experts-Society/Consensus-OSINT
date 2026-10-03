from consensus_osint.core.http import random_user_agent
from consensus_osint.core.provider_contracts import email_flag_outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def replit(email, client, out):
    name = "replit"
    domain = "replit.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        "User-Agent": random_user_agent(), "Accept": "application/json",
        "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
        "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://replit.com",
    }
    response = await client.post("https://replit.com/data/user/exists", headers=headers,
                                 json={"email": email}, follow_redirects=False)
    apply_mailbox_outcome(result, email_flag_outcome(response, "exists", email),
                         http_status=response.status_code)
