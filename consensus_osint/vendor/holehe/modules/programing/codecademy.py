from consensus_osint.core.codecademy_contracts import outcome, setup
from consensus_osint.core.http import random_user_agent
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def codecademy(email, client, out):
    name = "codecademy"
    domain = "codecademy.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        "User-Agent": random_user_agent(), "Accept": "application/json",
        "Accept-Language": "en,en-US;q=0.5",
        "Referer": "https://www.codecademy.com/register?redirect=%2F",
        "Content-Type": "application/json", "Origin": "https://www.codecademy.com",
    }
    response = await client.get("https://www.codecademy.com/register?redirect=%2F", headers=headers)
    token, issue = setup(response)
    if issue is not None:
        apply_mailbox_outcome(result, issue, http_status=response.status_code)
        return
    headers["X-CSRF-Token"] = token
    response = await client.post("https://www.codecademy.com/register/validate", headers=headers,
                                 json={"user": {"email": email}}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(response), http_status=response.status_code)
