import json

import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import email_flag_outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://mewe.com/api/v2/auth/check/user/email"
    show_url = "https://mewe.com"

    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "identity",
        "Content-Type": "application/json; charset=UTF-8",
        "sec-ch-ua-platform": '"Android"',
        "Origin": "https://mewe.com",
        "Referer": "https://mewe.com/register",
        "Priority": "u=1, i",
    }

    payload = {"email": email}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, content=json.dumps(payload), headers=headers, follow_redirects=False)

            status, _, reason = email_flag_outcome(response, "exists", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out! maybe region blocks")
    except httpx.ReadTimeout:
        return Result.error("Server took too long to respond (Read Timeout)")
    except Exception as e:
        return Result.error(e)


async def validate_mewe(email: str) -> Result:
    return await _check(email)
