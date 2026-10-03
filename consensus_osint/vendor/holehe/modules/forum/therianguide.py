from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def therianguide(email, client, out):
    name = "therianguide"
    domain = "forums.therian-guide.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://forums.therian-guide.com/member.php',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://forums.therian-guide.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }
    await check_mybb(email, client, out, name=name, domain=domain, method=method,
        frequent_rate_limit=frequent_rate_limit, base_url='https://forums.therian-guide.com/', headers=headers)
