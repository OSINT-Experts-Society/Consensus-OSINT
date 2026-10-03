from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import ua


async def seoclerks(email, client, out):
    name = "seoclerks"
    domain = "seoclerks.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["firefox"]),
        'Accept': '*/*',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.seoclerks.com',
        'Connection': 'keep-alive',
    }
    result = lookup_result(name, domain, method)
    response = await client.get('https://www.seoclerks.com', headers=headers)
    page = read_lookup_response(response, result, html=True)
    if page is None:
        out.append(result)
        return
    tokens = {}
    for key in ('token', '__cr'):
        inputs = page.select('input[name="' + key + '"]')
        token = inputs[0].get('value') if len(inputs) == 1 else None
        if not isinstance(token, str) or not token.strip():
            result['reason'] = 'The validation tokens were missing or ambiguous; no lookup was submitted.'
            out.append(result)
            return
        tokens[key] = token
    username = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
    password = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
    data = dict(tokens, fsub='1', droplet='', user_username=username, user_email=email,
                user_password=password, confirm_password=password)
    response = await client.post('https://www.seoclerks.com/signup/check', headers=headers, data=data)
    append_jobs_learning_outcome(response, out, name, domain, method, email)
