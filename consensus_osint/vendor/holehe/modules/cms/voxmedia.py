from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def voxmedia(email, client, out):
    name = "voxmedia"
    domain = "voxmedia.com"
    method="register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://auth.voxmedia.com/login',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://auth.voxmedia.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    data = {
        'email': email
    }

    result = lookup_result(name, domain, method)
    response = await client.post('https://auth.voxmedia.com/chorus_auth/email_valid.json', headers=headers, data=data)
    payload = read_lookup_response(response, result)
    if payload is not None:
        available, message = payload.get("available"), payload.get("message")
        if type(available) is bool and message in (None, ""):
            result["others"] = {"available": available}
            if available:
                result.update(exists=False, unknown=False, reason=None)
            else:
                result["reason"] = ("The registration service reports this email as unavailable; "
                                    "it did not establish that an account exists.")
        elif message == "You cannot use this email address.":
            result["reason"] = "The service rejected this email; rejection does not establish account presence or absence."
    out.append(result)
