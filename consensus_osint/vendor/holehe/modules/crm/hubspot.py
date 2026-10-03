from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def hubspot(email, client, out):
    name = "hubspot"
    domain = "hubspot.com"
    method= "login"
    frequent_rate_limit=False


    headers = {
        'authority': 'api.hubspot.com',
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'content-type': 'application/json',
        'origin': 'https://app.hubspot.com',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://app.hubspot.com/',
        'accept-language': 'en-US;q=0.8,en;q=0.7',
    }

    data = '{"email":"'+json.dumps(email)[1:-1]+'","password":"","rememberLogin":false}'

    response = await client.post('https://api.hubspot.com/login-api/v1/login', headers=headers, content=data)
    append_crm_outcome(response, out, name, domain, method, email)
