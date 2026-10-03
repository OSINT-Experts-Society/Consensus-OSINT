from consensus_osint.core.eventbrite_lookup import lookup
from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def eventbrite(email, client, out):
    name = "eventbrite"
    domain = "eventbrite.com"
    method = "login"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["firefox"]),
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://www.eventbrite.com/',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.eventbrite.com',
        'DNT': '1',
        'Connection': 'keep-alive',
    }

    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    status, fields, reason, code = await lookup(client.request, email, headers,
        signin_url="https://www.eventbrite.com/signin/?referrer=%2F", cookie_source=lambda: client.cookies)
    apply_mailbox_outcome(result, (status, fields, reason), http_status=code)
