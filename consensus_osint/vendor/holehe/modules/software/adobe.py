from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def adobe(email, client, out):
    name = "adobe"
    domain = "adobe.com"
    method = "password recovery"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'X-IMS-CLIENTID': 'adobedotcom2',
        'Content-Type': 'application/json;charset=utf-8',
        'Origin': 'https://auth.services.adobe.com',
        'DNT': '1',
        'Connection': 'keep-alive',
    }

    result = lookup_result(name, domain, method)
    out.append(result)
    response = await client.post("https://auth.services.adobe.com/signin/v1/authenticationstate",
                                 headers=headers, json={"username": email, "accountType": "individual"})
    state = read_lookup_response(response, result)
    if state is None:
        return
    token = response.headers.get("x-ims-authentication-state-encrypted")
    if not isinstance(token, str) or not token.strip():
        result["reason"] = "Required authentication-state header was missing; no challenge lookup was submitted."
        return
    headers["X-IMS-Authentication-State-Encrypted"] = token
    response = await client.get("https://auth.services.adobe.com/signin/v2/challenges",
                                headers=headers, params={"purpose": "passwordRecovery"})
    payload = read_lookup_response(response, result)
    if payload is None:
        return
    hints = {}
    for field, target in (("secondaryEmail", "emailrecovery"), ("securityPhoneNumber", "phoneNumber")):
        value = payload.get(field)
        if isinstance(value, str) and value.strip():
            hints[target] = value
    if hints:
        result.update(exists=True, unknown=False, reason=None, **hints)
    else:
        result["reason"] = "No meaningful recovery hints were returned; account status is unknown."
