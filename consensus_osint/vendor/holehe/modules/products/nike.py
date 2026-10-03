import json

from consensus_osint.core.http import random_user_agent
from consensus_osint.core.transport_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def nike(email, client, out):
    name = "nike"
    domain = "nike.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Content-Type': 'text/plain;charset=UTF-8',
        'Origin': 'https://www.nike.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Referer': 'https://www.nike.com/',
        'TE': 'Trailers',
    }
    headers["User-Agent"] = random_user_agent()
    params = {
        'appVersion': '831',
        'experienceVersion': '831',
        'uxid': 'com.nike.commerce.nikedotcom.web',
        'locale': 'fr_FR',
        'backendEnvironment': 'identity',
        'browser': '',
        'mobile': 'false',
        'native': 'false',
        'visit': '1',
    }
    response = await client.post("https://unite.nike.com/account/email/v1", headers=headers, params=params,
                                 content=json.dumps({"emailAddress": email}), follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
