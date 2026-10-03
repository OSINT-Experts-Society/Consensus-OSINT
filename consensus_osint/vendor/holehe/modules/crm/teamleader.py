from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def teamleader(email, client, out):
    name = "teamleader"
    domain = "teamleader.eu"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'authority': 'focus.teamleader.eu',
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'content-type': 'application/json',
        'accept': '*/*',
        'origin': 'https://signup.focus.teamleader.fr',
        'sec-fetch-site': 'cross-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://signup.focus.teamleader.fr/',
        'accept-language': 'en-US;q=0.8,en;q=0.7',
    }

    data = '{"email":"'+json.dumps(email)[1:-1]+'"}'

    response = await client.post('https://focus.teamleader.eu/app/emails/availability', headers=headers, content=data)
    append_crm_outcome(response, out, name, domain, method, email)
