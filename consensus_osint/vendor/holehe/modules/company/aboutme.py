from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def aboutme(email, client, out):
    name = "aboutme"
    domain = "about.me"
    method= "register"
    frequent_rate_limit=False

    result = lookup_result(name, domain, method)
    reqToken = await client.get("https://about.me/signup", headers={
        'User-Agent': random.choice(ua["browsers"]["firefox"])})
    if read_lookup_response(reqToken, result, html=True) is None:
        out.append(result)
        return
    tokens = re.findall(r'"AUTH_TOKEN"\s*:\s*("(?:[^"\\]|\\.)*")', reqToken.text)
    try:
        token = json.loads(tokens[0]) if len(tokens) == 1 else None
    except ValueError:
        token = None
    if not isinstance(token, str) or not token or any(ord(char) < 32 or ord(char) == 127 for char in token):
        result["reason"] = "The signup token was missing or ambiguous; no lookup was submitted."
        out.append(result)
        return
    headers = {
        'User-Agent': random.choice(ua["browsers"]["firefox"]),
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en-US,en;q=0.5',
        'X-Auth-Token': token,
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://about.me',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    data = '{"user_name":"","first_name":"","last_name":"","allowed_features":[],"counters":{"id":"counters"},"settings":{"id":"settings","compliments":{"id":"compliments"},"follow":{"id":"follow"},"share":{"id":"share"}},"email_address":"' + json.dumps(email)[1:-1] + \
        '","honeypot":"","actions":{"id":"actions"},"apps":[],"contact":{"id":"contact"},"contact_me":{"id":"contact_me"},"email_channels":{"id":"email_channels"},"flags":{"id":"flags"},"images":[],"interests":[],"jobs":[],"layout":{"version":1,"id":"layout","color":"305B90"},"links":[],"locations":[],"mapped_domains":[],"portfolio":[],"roles":[],"schools":[],"slack_teams":[],"spotlight":{"type":null,"text":null,"url":null,"id":"spotlight"},"spotlight_trial":{"type":null,"text":null,"url":null,"id":"spotlight_trial"},"store":{"id":"store","credit_card":{"number":"","exp_month":"","exp_year":"","cvc":"","address_zip":"","last4":"","id":"credit_card"},"charges":[],"purchases":[]},"tags":[],"testimonials":{"header":"0","id":"testimonials","items":[]},"video":{"id":"video"},"signup":{"id":"signup","step":"email","method":"email"}}'

    response = await client.post('https://about.me/n/signup', headers=headers, content=data)
    append_crm_outcome(response, out, name, domain, method, email)
