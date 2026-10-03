from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def amocrm(email, client, out):
    name = "amocrm"
    domain = "amocrm.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'Connection': 'keep-alive',
        'Accept': '*/*',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://www.amocrm.com',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://www.amocrm.com/',
        'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
    }

    data = {
      'LOGIN': email
    }

    result = lookup_result(name, domain, method)
    response = await client.post('https://www.amocrm.com/account/check_login.php', headers=headers, data=data)
    payload = read_lookup_response(response, result)
    if payload is not None and payload.get("status") in ("used", "free"):
        result.update(exists=payload["status"] == "used", unknown=False, reason=None)
    out.append(result)
