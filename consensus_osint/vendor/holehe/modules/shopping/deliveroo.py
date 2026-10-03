from consensus_osint.core.http import random_user_agent
from consensus_osint.core.transport_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def deliveroo(email, client, out):
    name = "deliveroo"
    domain = "deliveroo.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': 'application/json, application/vnd.api+json',
        'Accept-Language': 'en-US;q=0.5,en;q=0.3',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Roo-Client': 'orderweb-client',
        'X-Roo-Country': 'fr',
        'Content-Type': 'application/json;charset=UTF-8',
        'Origin': 'https://deliveroo.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.post("https://consumer-ow-api.deliveroo.com/orderapp/v1/check-email",
                                 headers=headers, json={"email_address": email}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
