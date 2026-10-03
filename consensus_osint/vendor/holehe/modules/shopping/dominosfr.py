from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.transport_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def dominosfr(email, client, out):
    name = "dominosfr"
    domain = "dominos.fr"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': 'text/html, */*; q=0.01',
        'Accept-Language': 'en,en-US;q=0.5',
        'X-Requested-With': 'XMLHttpRequest',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Referer': 'https://commande.dominos.fr/eStore/fr/Signup',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://commande.dominos.fr/eStore/fr/Signup", headers=headers)
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        apply_mailbox_outcome(result, (issue, {}, reason), http_status=response.status_code)
        return
    response = await client.get("https://commande.dominos.fr/eStore/fr/Signup/IsEmailAvailable",
                                headers=headers, params={"email": email}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
