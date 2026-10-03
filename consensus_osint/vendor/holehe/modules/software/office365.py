import random
import string
from urllib.parse import quote

from consensus_osint.core.autodiscover import routing_fields
from consensus_osint.vendor.holehe.core import append_http_error


async def office365(email, client, out):
    name = "office365"
    domain = "office365.com"
    method = "other"
    base = "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/"
    headers = {"User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro)",
               "Accept": "application/json"}

    async def request(address):
        return await client.get(base + quote(address, safe=""), params={"Protocol": "Autodiscoverv1"},
                                headers=headers, follow_redirects=False)

    control = "".join(random.choice(string.digits) for _ in range(30)) + "@" + email.rsplit("@", 1)[1]
    response = await request(control)
    if append_http_error(response, out, name, domain, method, accepted=(200, 404)):
        return
    fields = None
    if response.status_code == 404:
        response = await request(email)
        if append_http_error(response, out, name, domain, method, accepted=(200, 404)):
            return
        fields = routing_fields(response)
        reason = "Response did not provide a validated Autodiscover route; mailbox state is unknown"
    elif routing_fields(response):
        reason = "Domain also routes a random address; this does not distinguish the queried account"
    else:
        reason = "Control request returned an unrecognised Autodiscover response"
    out.append({"name": name, "domain": domain, "method": method, "frequent_rate_limit": False,
                "rateLimit": False, "exists": True if fields else None, "unknown": not bool(fields),
                "reason": None if fields else reason, "emailrecovery": None, "phoneNumber": None,
                "others": fields})
