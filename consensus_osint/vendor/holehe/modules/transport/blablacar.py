from urllib.parse import quote

from consensus_osint.core.http import random_user_agent
from consensus_osint.core.transport_email_contracts import outcome, page_token
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def blablacar(email, client, out):
    name = "blablacar"
    domain = "blablacar.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': 'application/json',
        'Accept-Language': 'fr_FR',
        'Referer': 'https://www.blablacar.fr/',
        'Content-Type': 'application/json',
        'x-locale': 'fr_FR',
        'x-currency': 'EUR',
        'x-client': 'SPA|1.0.0',
        'x-forwarded-proto': 'https',
        'Origin': 'https://www.blablacar.fr',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://www.blablacar.fr/register", headers=headers)
    token, issue = page_token(response, "appToken")
    if issue is not None:
        apply_mailbox_outcome(result, issue, http_status=response.status_code)
        return
    headers["Authorization"] = "Bearer " + token
    response = await client.get("https://edge.blablacar.fr/auth/validation/email/" + quote(email, safe=""),
                                headers=headers, cookies={"datadome": ""}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
