import httpx

from consensus_osint.vendor.user_scanner.core.result import Result
from consensus_osint.core.jobs_learning_contracts import outcome
from consensus_osint.core.models import Status


async def _check(email: str) -> Result:
    show_url = "https://duolingo.com"
    headers = {
        "authority": "www.duolingo.com",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Referer": "https://www.duolingo.com/",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(
                "https://www.duolingo.com/2017-06-30/users",
                params={"email": email},
                headers=headers,
            )

            status, fields, reason = outcome('duolingo', response, email)
            if status is Status.FOUND:
                avatar = fields.pop('avatar', None)
                extra = {key: value for key, value in fields.items() if not isinstance(value, list)}
                return Result.taken(extra=extra, media={'avatar': avatar} if avatar else {}, url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason)
    except httpx.TimeoutException:
        return Result.error('Provider request timed out; account status is unknown.')
    except Exception:
        return Result.error('Provider request failed; account status is unknown.')


async def validate_duolingo(email: str) -> Result:
    return await _check(email)
