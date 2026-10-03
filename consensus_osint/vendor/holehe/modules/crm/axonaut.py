from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def axonaut(email, client, out):
    name = "axonaut"
    domain = "axonaut.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'authority': 'axonaut.com',
        'upgrade-insecure-requests': '1',
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-user': '?1',
        'sec-fetch-dest': 'document',
        'referer': 'https://axonaut.com/en',
        'accept-language': 'en-US;q=0.8,en;q=0.7',
    }


    response = await client.get('https://axonaut.com/onboarding/', params={'email': email}, headers=headers,follow_redirects=False)
    append_crm_outcome(response, out, name, domain, method, email)
