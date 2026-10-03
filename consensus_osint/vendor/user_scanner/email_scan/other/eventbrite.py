import httpx
from consensus_osint.core.eventbrite_lookup import lookup
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://eventbrite.com"
    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.9',
        'Referer': 'https://www.eventbrite.com/signin/',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.eventbrite.com',
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            status, fields, reason, _ = await lookup(client.request, email, headers, cookie_source=lambda: client.cookies)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=fields)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(e)


async def validate_eventbrite(email: str) -> Result:
    return await _check(email)
