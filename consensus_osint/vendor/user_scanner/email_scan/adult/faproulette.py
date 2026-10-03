import httpx

from consensus_osint.core.adult_email_contracts import user_scanner_outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://faproulette.co"
    url = "https://faproulette.co/api/userCheckEmail"

    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": show_url,
        "Referer": show_url + "/",
    }
    payload = {"email": email, "timeoutID": 1}

    try:
        async with httpx.AsyncClient(http2=True, timeout=15.0) as client:
            response = await client.post(url, data=payload, headers=headers, follow_redirects=False)
            status, _, reason = user_scanner_outcome(response, "faproulette", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(e)


async def validate_faproulette(email: str) -> Result:
    return await _check(email)
