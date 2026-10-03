from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def archive(email, client, out):
    name = "archive"
    domain = "archive.org"
    method = "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Content-Type': 'multipart/form-data; boundary=---------------------------',
        'Origin': 'https://archive.org',
        'Connection': 'keep-alive',
        'Referer': 'https://archive.org/account/signup',
        'Sec-GPC': '1',
        'TE': 'Trailers',
    }

    data = '-----------------------------\r\nContent-Disposition: form-data; name="input_name"\r\n\r\nusername\r\n-----------------------------\r\nContent-Disposition: form-data; name="input_value"\r\n\r\n' + email + \
        '\r\n-----------------------------\r\nContent-Disposition: form-data; name="input_validator"\r\n\r\ntrue\r\n-----------------------------\r\nContent-Disposition: form-data; name="submit_by_js"\r\n\r\ntrue\r\n-------------------------------\r\n'

    response = await client.post('https://archive.org/account/signup', headers=headers, data=data)
    if append_http_error(response, out, name, domain, method):
        return
    if "is already taken." in response.text:
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
