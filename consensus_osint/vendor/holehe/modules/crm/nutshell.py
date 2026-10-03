from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def nutshell(email, client, out):
    name = "nutshell"
    domain = "nutshell.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'authority': 'app.nutshell.com',
        'accept': '*/*',
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://app.nutshell.com',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://app.nutshell.com/auth',
        'accept-language': 'en-US;q=0.8,en;q=0.7',
    }

    data = {
      'via': 'database',
      'timezone_offset': '1',
      'remember_me': 'true',
      'username': email,
      'invalidToken': 'false',
      'password': 'a'
    }

    response = await client.post('https://app.nutshell.com/auth', headers=headers, data=data)
    append_crm_outcome(response, out, name, domain, method, email)
