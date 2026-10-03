import json

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://registerdisney.go.com/jgc/v8/client/ESPN-ONESITE.WEB-PROD/guest-flow"
    show_url = "https://espn.com"
    params = {
        'langPref': "en",
        'feature': "no-password-reuse"
    }
    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'Content-Type': "application/json",
        'origin': "https://cdn.registerdisney.go.com",
        'referer': "https://cdn.registerdisney.go.com/",
        'accept-language': "en-US,en;q=0.9",
    }
    payload = {"email": email}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                url,
                params=params,
                json=payload,
                headers=headers, follow_redirects=False
            )

            issue, reason = http_issue(response.status_code, response.headers, response.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            data = json.loads(response.text, object_pairs_hook=_unique_object)
            if not isinstance(data, dict):
                return Result.error("Invalid guest-flow envelope", url=show_url)
            body = data.get("data")
            for record in (data, body):
                if (not isinstance(record, dict) or has_service_error(record)
                        or "email" in record and (not isinstance(record["email"], str) or record["email"].casefold() != email.casefold())):
                    return Result.error("Conflicting guest-flow response", url=show_url)
            extra = {"scope": "Disney identity sign-in routing; does not establish ESPN activity"}
            if body.get("guestFlow") == "LOGIN_FLOW":
                return Result.taken(url=show_url, extra=extra)
            if body.get("guestFlow") == "REGISTRATION_FLOW":
                return Result.available(url=show_url, extra=extra)
            return Result.error("No supported Disney guest-flow response", url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(f"Unexpected Exception: {e}")


async def validate_espn(email: str) -> Result:
    return await _check(email)
