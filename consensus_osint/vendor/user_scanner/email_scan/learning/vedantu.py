import json

import httpx

from consensus_osint.core.learning_validation_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://user.vedantu.com/user/preLoginVerification"
    show_url = "https://www.vedantu.com"

    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        'Accept': "application/json, text/plain, */*",
        'Accept-Encoding': "identity",
        'Content-Type': "application/json;charset=UTF-8",
        'sec-ch-ua-platform': '"Linux"',
        'Origin': "https://www.vedantu.com",
        'Referer': "https://www.vedantu.com/",
        'Priority': "u=1, i"
    }

    payload = {
        "email": email,
        "phoneCode": None,
        "phoneNumber": None,
        "version": 2,
        "ver": 1.033,
        "token": "",
        "sType": "",
        "sValue": "",
        "event": "NEW_FLOW"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.post(
                url,
                content=json.dumps(payload),
                headers=headers, follow_redirects=False
            )

            status, extra, reason = outcome(response, "vedantu", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out! maybe region blocks")
    except httpx.ReadTimeout:
        return Result.error("Server took too long to respond (Read Timeout)")
    except Exception as e:
        return Result.error(e)

async def validate_vedantu(email: str) -> Result:
    return await _check(email)
