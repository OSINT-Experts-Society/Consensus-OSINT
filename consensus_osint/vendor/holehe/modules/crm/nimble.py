from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def nimble(email, client, out):
    name = "nimble"
    domain = "nimble.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'Connection': 'keep-alive',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://www.nimble.com/',
        'Accept-Language': 'en-US;q=0.8,en;q=0.7',
    }

    response = await client.get('https://www.nimble.com/lib/register.php', params={'email': email}, headers=headers)
    append_crm_outcome(response, out, name, domain, method, email)
