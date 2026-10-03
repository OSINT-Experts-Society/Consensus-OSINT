from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def armurerieauxerre(email, client, out):
    name = "armurerieauxerre"
    domain = "armurerie-auxerre.com"
    method = "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': '*/*',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.armurerie-auxerre.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    data = {
        'mail': email
    }

    req = await client.post('https://www.armurerie-auxerre.com/customer/Email/email/', headers=headers, data=data)
    if append_http_error(req, out, name, domain, method):
        return
    if req.text == "exist":
        out.append({"name": name,"domain":domain,"method":method,"frequent_rate_limit":frequent_rate_limit,
                    "rateLimit": False,
                    "exists": True,
                    "emailrecovery": None,
                    "phoneNumber": None,
                    "others": None})
    else:
        out.append({"name": name,"domain":domain,"method":method,"frequent_rate_limit":frequent_rate_limit,
                    "rateLimit": False,
                    "exists": None, "unknown": True, "reason": "Response did not contain a validated account-absence signal",
                    "emailrecovery": None,
                    "phoneNumber": None,
                    "others": None})
