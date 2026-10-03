import httpx
import json
from consensus_osint.core.media_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://www.komoot.com"
    url = "https://www.komoot.com/v1/signin"

    payload = {
        "email": email,
        "reason": "header",
        "new_tab": False
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json, text/plain, */*",
        'Accept-Encoding': "identity",
        'Content-Type': "application/json",
        'sec-ch-ua-platform': '"Android"',
        'sec-ch-ua': '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        'sec-ch-ua-mobile': "?1",
        'origin': "https://www.komoot.com",
        'sec-fetch-site': "same-origin",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'referer': "https://www.komoot.com/signin?referrer=www.google.com&reason=header",
        'accept-language': "en-US,en;q=0.9",
        'priority': "u=1, i"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, content=json.dumps(payload), headers=headers)
            status, _, reason = outcome("komoot", response, email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out! maybe region blocks")
    except Exception:
        return Result.error("Komoot request failed; account status is unknown.")


async def validate_komoot(email: str) -> Result:
    return await _check(email)
