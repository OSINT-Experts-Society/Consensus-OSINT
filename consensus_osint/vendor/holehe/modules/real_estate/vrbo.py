from consensus_osint.core.http import random_user_agent
from consensus_osint.core.transport_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def vrbo(email, client, out):
    name = "vrbo"
    domain = "vrbo.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/json',
        'x-homeaway-site': 'vrbo',
        'Origin': 'https://www.vrbo.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.post("https://www.vrbo.com/auth/aam/v3/status", headers=headers,
                                 json={"emailAddress": email}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
