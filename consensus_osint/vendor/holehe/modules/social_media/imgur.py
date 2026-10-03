from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.social_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def imgur(email, client, out):
    name = "imgur"
    domain = "imgur.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://imgur.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://imgur.com/register?redirect=%2Fuser", headers=headers)
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        apply_mailbox_outcome(result, (issue, {}, reason), http_status=response.status_code)
        return
    headers["X-Requested-With"] = "XMLHttpRequest"
    response = await client.post("https://imgur.com/signin/ajax_email_available", headers=headers,
                                 data={"email": email}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
