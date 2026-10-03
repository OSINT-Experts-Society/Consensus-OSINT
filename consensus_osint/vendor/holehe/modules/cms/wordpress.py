from urllib.parse import quote
from consensus_osint.core.provider_contracts import wordpress_lookup
from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def wordpress(email, client, out):
    name = "wordpress"
    domain = "wordpress.com"
    method= "login"
    frequent_rate_limit=False

    cookies = {
        'G_ENABLED_IDPS': 'google',
        'ccpa_applies': 'true',
        'usprivacy': '1YNN',
        'landingpage_currency': 'EUR',
        'wordpress_test_cookie': 'WP+Cookie+check',
    }

    headers = {
        'User-Agent': random.choice(ua["browsers"]["firefox"]),
        'Accept': '*/*',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    params = {
        'http_envelope': '1',
        'locale': 'fr',
    }
    result = lookup_result(name, domain, method)
    response = await client.get(
        "https://public-api.wordpress.com/rest/v1.1/users/" + quote(email, safe="") + "/auth-options",
        headers=headers, params=params, cookies=cookies)
    data = read_lookup_response(response, result)
    if data is not None:
        exists, extra, reason = wordpress_lookup(data)
        result.update(exists=exists, unknown=exists is None, reason=reason)
        if exists is None and type(data.get("code")) is int:
            result.update(rateLimit=data["code"] == 429,
                          blocked=data["code"] in (401, 403, 406, 407, 418, 451))
        if extra:
            result["others"] = extra
    out.append(result)
