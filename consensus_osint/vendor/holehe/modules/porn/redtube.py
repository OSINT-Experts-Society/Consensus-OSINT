from consensus_osint.core.adult_email_contracts import outcome, prerequisite
from consensus_osint.core.http import random_user_agent
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def redtube(email, client, out):
    name = "redtube"
    domain = "redtube.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US;q=0.5,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://redtube.com',
        'DNT': '1',
        'Connection': 'keep-alive',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://redtube.com/register", headers=headers)
    token, problem = prerequisite(response, name)
    if problem is not None:
        apply_mailbox_outcome(result, problem, http_status=response.status_code)
        return
    data = {"check_what": "email", "email": email}
    headers["X-Requested-With"] = "XMLHttpRequest"
    data.update(token=token, redirect="")
    response = await client.post("https://www.redtube.com/user/create_account_check", headers=headers,
                                 params={"token": token}, data=data, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(response, name, email), http_status=response.status_code)
