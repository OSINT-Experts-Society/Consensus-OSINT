import json

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://stremio.com"
    url = "https://api.strem.io/api/login"

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
        'Content-Type': "application/json",
        'Origin': "https://www.stremio.com",
        'Referer': "https://www.stremio.com/",
        'Accept-Language': "en-US,en;q=0.9",
    }

    payload = {
        "authKey": None,
        "email": email,
        "password": "wrongpassword123"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers, follow_redirects=False)

            issue, reason = http_issue(response.status_code, response.headers, response.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            data = json.loads(response.text, object_pairs_hook=_unique_object)
            if not isinstance(data, dict) or has_service_error({k: v for k, v in data.items() if k != "error"}):
                return Result.error("Invalid or failed authentication lookup", url=show_url)
            error_data = data.get("error")
            if not isinstance(error_data, dict) or has_service_error(error_data):
                return Result.error("No supported authentication flags", url=show_url)
            for record in (data, error_data):
                if "email" in record and (not isinstance(record["email"], str) or record["email"].casefold() != email.casefold()):
                    return Result.error("Authentication response returned a different email", url=show_url)
            flags = [error_data.get(key, False) for key in ("wrongPass", "wrongEmail")]
            if any(type(flag) is not bool for flag in flags) or sum(flags) != 1:
                return Result.error("Missing or conflicting authentication flags", url=show_url)
            # A wrong-password flag is not a positive account contract. Retain
            # the distinct wrong-email negative only; generic credentials fail
            # inconclusively, without claiming an existing account.
            if flags[1]:
                return Result.available(url=show_url)
            return Result.error("Wrong password does not establish account existence", url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(f"Unexpected Exception: {e}")


async def validate_stremio(email: str) -> Result:
    return await _check(email)
