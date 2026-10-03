from consensus_osint.core.adult_email_contracts import outcome, prerequisite
from consensus_osint.core.http import random_user_agent
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def pornhub(email, client, out):
    name = "pornhub"
    domain = "pornhub.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en,en-US;q=0.5',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://www.pornhub.com/signup", headers=headers)
    token, problem = prerequisite(response, name)
    if problem is not None:
        apply_mailbox_outcome(result, problem, http_status=response.status_code)
        return
    data = {"check_what": "email", "email": email}
    response = await client.post("https://www.pornhub.com/user/create_account_check", headers=headers,
                                 params={"token": token}, data=data, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(response, name, email), http_status=response.status_code)
