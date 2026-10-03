from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def bitmoji(email, client, out):
    name = "bitmoji"
    domain = "bitmoji.com"
    method = "login"
    frequent_rate_limit=False

    result = lookup_result(name, domain, method)
    out.append(result)
    response = await client.get("https://accounts.snapchat.com")
    page = read_lookup_response(response, result, html=True)
    if page is None:
        return
    tokens = {(node.get("data-xsrf"), node.get("data-web-client-id"))
              for node in page.select("[data-xsrf][data-web-client-id]")}
    if len(tokens) != 1 or not all(value and value.strip() for value in next(iter(tokens))):
        result["reason"] = "Required login tokens were missing or ambiguous; no email lookup was submitted."
        return
    xsrf, web_client_id = tokens.pop()
    headers = {"Host": "accounts.snapchat.com", "User-Agent": random.choice(ua["browsers"]["firefox"]),
               "Accept": "*/*", "X-XSRF-TOKEN": xsrf, "Accept-Encoding": "gzip, deflate",
               "Content-Type": "application/json", "Connection": "close",
               "Cookie": "xsrf_token=" + xsrf + "; web_client_id=" + web_client_id}
    response = await client.post("https://accounts.snapchat.com/accounts/merlin/login",
                                 json={"email": email, "app": "BITMOJI_APP"}, headers=headers)
    payload = read_lookup_response(response, result)
    if payload is not None and type(payload.get("hasBitmoji")) is bool:
        result.update(exists=payload["hasBitmoji"], unknown=False, reason=None)
