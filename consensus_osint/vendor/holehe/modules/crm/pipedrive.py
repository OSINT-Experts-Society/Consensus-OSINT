from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def pipedrive(email, client, out):
    name = "pipedrive"
    domain = "pipedrive.com"
    method= "register"
    frequent_rate_limit=False


    headers = {
        'authority': 'app.pipedrive.com',
        'accept': 'application/json',
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'content-type': 'application/json',
        'origin': 'https://www.pipedrive.com',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://www.pipedrive.com/',
        'accept-language': 'en-US;q=0.8,en;q=0.7',
    }
    data = '{"email":"'+json.dumps(email)[1:-1]+'","language":"fr","country_code":"fr","selectedTier":null,"packages":[]}'

    response = await client.post('https://app.pipedrive.com/signup-service/start', headers=headers, content=data)
    append_crm_outcome(response, out, name, domain, method, email)
