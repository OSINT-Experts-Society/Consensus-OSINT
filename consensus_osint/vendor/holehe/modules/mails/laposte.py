import random

from bs4 import BeautifulSoup

from consensus_osint.vendor.holehe.core import append_http_error
from consensus_osint.vendor.holehe.localuseragent import ua


async def laposte(email, client, out):
    name = "laposte"
    domain = "laposte.fr"
    method = "login"
    headers = {
        "Origin": "https://www.laposte.fr",
        "User-Agent": random.choice(ua["browsers"]["chrome"]),
        "Accept": "text/html",
        "Referer": "https://www.laposte.fr/authentification",
        "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    response = await client.post(
        "https://www.laposte.fr/authentification", headers=headers,
        data={"email": email, "customerId": "", "tunnelSteps": ""},
    )
    if append_http_error(response, out, name, domain, method):
        return
    marker = BeautifulSoup(response.content, "html.parser").find("span", id="wrongEmail")
    # This generic form element may be empty or hidden. No retained evidence
    # validates its presence or absence as a query-specific account verdict.
    reason = ("Authentication page contains wrongEmail; this form marker alone does not establish account existence"
              if marker is not None else "Unrecognised authentication response")
    out.append({"name": name, "domain": domain, "method": method, "frequent_rate_limit": False,
                "rateLimit": False, "exists": None, "unknown": True, "reason": reason,
                "emailrecovery": None, "phoneNumber": None, "others": None})
