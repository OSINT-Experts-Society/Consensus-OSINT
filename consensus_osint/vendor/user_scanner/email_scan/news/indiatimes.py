import json

import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.music_identity_contracts import outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://timesofindia.com"
    url = "https://jsso.indiatimes.com/sso/crossapp/identity/web/checkUserExists"

    payload = {
        "identifier": email
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
        'Content-Type': "application/json",
        'sdkversion': "0.8.1",
        'channel': "toi",
        'platform': "WAP",
        'Origin': "https://timesofindia.indiatimes.com",
        'Referer': "https://timesofindia.indiatimes.com/",
    }

    try:

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, content=json.dumps(payload), headers=headers, follow_redirects=False)

            status, extra, reason = outcome(response, "indiatimes", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url, extra=extra)
            return Result.error(reason, url=show_url)

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out! maybe region blocks")
    except httpx.ReadTimeout:
        return Result.error("Server took too long to respond (Read Timeout)")
    except Exception as e:
        return Result.error(e)


async def validate_indiatimes(email: str) -> Result:
    return await _check(email)
