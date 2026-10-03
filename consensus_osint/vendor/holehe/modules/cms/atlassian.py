import html

from consensus_osint.core.provider_contracts import atlassian_lookup
from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def atlassian(email, client, out):
    name = "atlassian"
    domain = "atlassian.com"
    method="register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://id.atlassian.com/',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://id.atlassian.com',
        'DNT': '1',
        'Connection': 'keep-alive',
    }
    result = lookup_result(name, domain, method)
    out.append(result)
    response = await client.get("https://id.atlassian.com/login", headers=headers)
    if read_lookup_response(response, result, html=True) is None:
        return
    # Decode a JSON string value rather than treating escaped text as a token.
    values = re.findall(r'"csrfToken"\s*:\s*("(?:\\.|[^"\\])*")', html.unescape(response.text))
    try:
        tokens = {json.loads(value) for value in values}
    except ValueError:
        tokens = set()
    if len(tokens) != 1 or not next(iter(tokens)).strip():
        result["reason"] = "Required CSRF token was missing or ambiguous; no email lookup was submitted."
        return
    response = await client.post("https://id.atlassian.com/rest/check-username", headers=headers,
                                 data={"csrfToken": tokens.pop(), "username": email})
    payload = read_lookup_response(response, result)
    if payload is None:
        return
    exists, extra, reason = atlassian_lookup(payload)
    result.update(exists=exists, unknown=exists is None, reason=reason)
    if extra:
        result["others"] = extra
