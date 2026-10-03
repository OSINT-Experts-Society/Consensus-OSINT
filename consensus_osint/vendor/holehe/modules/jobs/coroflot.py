from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def coroflot(email, client, out):
    name = "coroflot"
    domain = "coroflot.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["firefox"]),
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.coroflot.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Referer': 'https://www.coroflot.com/signup',
        'TE': 'Trailers',
    }
    result = lookup_result(name, domain, method)
    response = await client.get('https://www.coroflot.com/signup', headers=headers)
    page = read_lookup_response(response, result, html=True)
    if page is None:
        out.append(result)
        return
    inputs = page.select('#sign_up_new_flow input[name="__RequestVerificationToken"]')
    token = inputs[0].get('value') if len(inputs) == 1 else None
    if not isinstance(token, str) or not token.strip():
        result['reason'] = 'The verification token was missing or ambiguous; no lookup was submitted.'
        out.append(result)
        return
    response = await client.post('https://www.coroflot.com/home/signup_email_check', headers=headers,
        data={'email': email, '__RequestVerificationToken': token})
    append_jobs_learning_outcome(response, out, name, domain, method, email)
