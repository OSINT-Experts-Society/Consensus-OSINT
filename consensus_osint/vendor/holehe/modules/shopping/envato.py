from consensus_osint.core.dev_email_contracts import outcome
from consensus_osint.core.http import random_user_agent
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def envato(email, client, out):
    name = "envato"
    domain = "envato.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        "User-Agent": random_user_agent(),
        "Accept": "application/json",
        "Accept-Language": "en,en-US;q=0.5",
        "Content-type": "application/x-www-form-urlencoded",
        "DNT": "1",
        "Connection": "keep-alive",
        "TE": "Trailers",
    }
    response = await client.post("https://account.envato.com/api/validate_email", headers=headers,
                                 data={"email": email}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(response, "envato-legacy", email), http_status=response.status_code)
