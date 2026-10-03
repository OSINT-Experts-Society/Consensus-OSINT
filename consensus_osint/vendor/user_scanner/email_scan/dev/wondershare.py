import json

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    csrf_url = "https://accounts.wondershare.com/api/v3/csrf-token"
    inspect_url = "https://accounts.wondershare.com/api/v3/account/inspect"
    show_url = "https://wondershare.com"

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json, text/plain, */*",
        'Accept-Encoding': "identity",
        'sec-ch-ua-platform': '"Android"',
        'x-lang': "en-us",
        'sec-ch-ua': '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        'sec-ch-ua-mobile': "?1",
        'sec-fetch-site': "same-origin",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'referer': "https://accounts.wondershare.com/m/login?source=&redirect_uri=https://www.wondershare.com/?source=&site=www.wondershare.com&verify=no",
        'accept-language': "en-US,en;q=0.9",
        'priority': "u=1, i"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:

            r_csrf = await client.get(csrf_url, headers=headers, follow_redirects=False)
            issue, reason = http_issue(r_csrf.status_code, r_csrf.headers, r_csrf.text)
            if issue is not None:
                return Result.error(reason)

            token = client.cookies.get("req_identity")

            if not valid_token(token):
                return Result.error("req_identity cookie missing from handshake")

            inspect_headers = headers.copy()
            inspect_headers.update({
                'x-csrf-token': token,
                'Content-Type': "application/json",
                'origin': "https://accounts.wondershare.com",
                'referer': "https://accounts.wondershare.com/m/register"
            })

            payload = {"email": email}

            response = await client.put(
                inspect_url,
                content=json.dumps(payload),
                headers=inspect_headers, follow_redirects=False
            )

            issue, reason = http_issue(response.status_code, response.headers, response.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            data_final = json.loads(response.text, object_pairs_hook=_unique_object)
            if not isinstance(data_final, dict) or has_service_error(data_final):
                return Result.error("Invalid or failed account lookup", url=show_url)
            status_obj = data_final.get("data")
            if not isinstance(status_obj, dict) or has_service_error(status_obj):
                return Result.error("Invalid or failed account data", url=show_url)
            for record in (data_final, status_obj):
                if "email" in record and (not isinstance(record["email"], str) or record["email"].casefold() != email.casefold()):
                    return Result.error("Account lookup returned a different email", url=show_url)
            status_code = status_obj.get("exist")
            if type(status_code) is not int:
                return Result.error("Account existence code is not an integer", url=show_url)

            # 1 = Registered, 2 = Not Registered
            if status_code == 1:
                return Result.taken(url=show_url)
            elif status_code == 2:
                return Result.available(url=show_url)

            return Result.error(f"Unexpected exist value: {status_code}")

    except Exception as e:
        return Result.error(e)


async def validate_wondershare(email: str) -> Result:
    return await _check(email)
