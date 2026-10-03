from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def buymeacoffee(email, client, out):
    name = "buymeacoffee"
    domain = "buymeacoffee.com"
    method= "register"
    frequent_rate_limit=True

    def get_random_string(length):
        letters = string.ascii_lowercase
        result_str = ''.join(random.choice(letters) for i in range(length))
        return(result_str)
    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.buymeacoffee.com',
        'DNT': '1',
        'TE': 'Trailers',
    }
    result = lookup_result(name, domain, method)
    result['frequent_rate_limit'] = frequent_rate_limit
    response = await client.get('https://www.buymeacoffee.com/', headers=headers)
    page = read_lookup_response(response, result, html=True)
    if page is None:
        out.append(result)
        return
    inputs = page.select('input[name="bmc_csrf_token"]')
    token = inputs[0].get('value') if len(inputs) == 1 else None
    if not isinstance(token, str) or not token.strip():
        result['reason'] = 'The validation token was missing or ambiguous; no lookup was submitted.'
        out.append(result)
        return
    response = await client.post('https://www.buymeacoffee.com/auth/validate_email_and_password',
        headers=headers, cookies={'bmccsrftoken': token},
        data={'email': email, 'password': get_random_string(20), 'bmc_csrf_token': token})
    data = read_lookup_response(response, result)
    if data is not None:
        # No retained duplicate-specific contract or controlled negative evidence.
        # Credential-validation success also does not establish account absence.
        result['reason'] = ('Registration validation does not establish whether an account exists; '
                            'the account-response contract remains unverified.')
    out.append(result)
