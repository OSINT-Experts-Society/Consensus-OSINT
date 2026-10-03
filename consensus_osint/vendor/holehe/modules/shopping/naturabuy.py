from consensus_osint.core.http import random_user_agent
from consensus_osint.core.provider_contracts import email_flag_outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def naturabuy(email, client, out):
    name = "naturabuy"
    domain = "naturabuy.fr"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        "User-Agent": random_user_agent(), "Accept": "*/*",
        "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
        "X-Requested-With": "XMLHttpRequest", "Origin": "https://www.naturabuy.fr",
    }
    files = {"jsref": (None, "email"), "jsvalue": (None, email), "registerMode": (None, "full")}
    response = await client.post("https://www.naturabuy.fr/includes/ajax/register.php",
                                 headers=headers, files=files, follow_redirects=False)
    apply_mailbox_outcome(result, email_flag_outcome(response, "free", email, true_means_available=True),
                         http_status=response.status_code)
