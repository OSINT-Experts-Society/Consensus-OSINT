from urllib.parse import quote
from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def zoho(email, client, out):
    name = "zoho"
    domain = "zoho.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Accept': '*/*',
        'Origin': 'https://accounts.zoho.com',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Language': 'en-US;q=0.8,en;q=0.7',
    }

    result = lookup_result(name, domain, method)
    response = await client.get("https://accounts.zoho.com/register", headers=headers)
    if read_lookup_response(response, result, html=True) is None:
        out.append(result)
        return
    try:
        token = response.cookies.get("iamcsr")
    except httpx.CookieConflict:
        token = None
    if not token:
        result["reason"] = "The lookup cookie was missing or ambiguous; no lookup was submitted."
        out.append(result)
        return
    headers['X-ZCSRF-TOKEN'] = 'iamcsrcoo=' + token

    data = {
      'mode': 'primary',
      'servicename': 'ZohoCRM',
      'serviceurl': 'https://crm.zoho.com/crm/ShowHomePage.do',
      'service_language': 'fr'
    }

    response = await client.post('https://accounts.zoho.com/signin/v2/lookup/'+quote(email, safe=''), headers=headers, data=data)
    append_crm_outcome(response, out, name, domain, method, email)
