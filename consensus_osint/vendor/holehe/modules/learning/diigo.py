from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def diigo(email, client, out):
    name = "diigo"
    domain = "diigo.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["firefox"]),
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Referer': 'https://www.diigo.com/sign-up?plan=free',
        'X-Requested-With': 'XMLHttpRequest'
    }
    response = await client.get('https://www.diigo.com/user_mana2/check_email', headers=headers, params={'email': email})
    append_jobs_learning_outcome(response, out, name, domain, method, email)
