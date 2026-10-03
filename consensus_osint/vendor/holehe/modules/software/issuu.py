from urllib.parse import quote

from consensus_osint.core.http import random_user_agent
from consensus_osint.core.software_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def issuu(email, client, out):
    name = "issuu"
    domain = "issuu.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://issuu.com/signup?returnUrl=https%3A%2F%2Fissuu.com%2F&issuu_product=header&issuu_subproduct=anon_home&issuu_context=signin&issuu_cta=log_up',
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://issuu.com/call/signup/check-email/" + quote(email, safe=""),
                                headers=headers, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
