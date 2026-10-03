from consensus_osint.core.http import random_user_agent
from consensus_osint.core.provider_contracts import literal_email_outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def plurk(email, client, out):
    name = "plurk"
    domain = "plurk.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'User-Agent': random_user_agent(),
        'Accept': '*/*',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.plurk.com',
        'DNT': '1',
        'Connection': 'keep-alive',
    }

    response = await client.post("https://www.plurk.com/Users/isEmailFound", headers=headers,
                                 data={"email": email}, follow_redirects=False)
    apply_mailbox_outcome(result, literal_email_outcome(response, "True", "False"), http_status=response.status_code)
