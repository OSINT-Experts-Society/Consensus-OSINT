from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *
from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import email_flag_outcome


async def anydo(email, client, out):
    name = "anydo"
    domain = "any.do"
    method= "login"
    frequent_rate_limit=True

    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://desktop.any.do/',
        'Content-Type': 'application/json; charset=UTF-8',
        'X-Platform': '3',
        'Origin': 'https://desktop.any.do',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    try:
        response = await client.post('https://sm-prod2.any.do/check_email', headers=headers, json={"email": email})
        apply_mailbox_outcome(result, email_flag_outcome(response, "user_exists", email), http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Provider request failed; account status is unknown."))
