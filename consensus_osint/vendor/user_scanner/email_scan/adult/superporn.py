import httpx

from consensus_osint.core.adult_email_contracts import user_scanner_outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://superporn.com"
    url = "https://api.superporn.com/signup/check-email"

    payload = {
        'lang': "en_US",
        'email': email
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json, text/javascript, */*; q=0.01",
        'Origin': "https://www.superporn.com",
        'Referer': "https://www.superporn.com/signup",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, data=payload, headers=headers, follow_redirects=False)
            status, _, reason = user_scanner_outcome(response, "superporn", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(e)


async def validate_superporn(email: str) -> Result:
    return await _check(email)
