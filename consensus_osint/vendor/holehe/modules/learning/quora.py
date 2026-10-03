from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def quora(email, client, out):
    name = "quora"
    domain = "quora.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["firefox"]),
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://fr.quora.com',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }
    result = lookup_result(name, domain, method)
    response = await client.get('https://fr.quora.com', headers=headers)
    page = read_lookup_response(response, result, html=True)
    if page is None:
        out.append(result)
        return
    tokens = {}
    for key in ('revision', 'formkey'):
        # Parse quoted JSON values without interpolating user input into JSON.
        pattern = r'"' + key + r'"\s*:\s*("(?:\\.|[^"\\])*")'
        values = [json.loads(match) for script in page.find_all('script') for match in re.findall(pattern, script.get_text())]
        if len(values) != 1 or not isinstance(values[0], str) or not values[0].strip():
            result['reason'] = 'The validation tokens were missing or ambiguous; no lookup was submitted.'
            out.append(result)
            return
        tokens[key] = values[0]
    data = {'json': json.dumps({'args': [], 'kwargs': {'value': email}}), 'formkey': tokens['formkey'],
            '__hmac': '0XXXXXXxxXDxX', '__method': 'validate'}
    response = await client.post('https://fr.quora.com/webnode2/server_call_POST', headers=headers, data=data)
    append_jobs_learning_outcome(response, out, name, domain, method, email)
