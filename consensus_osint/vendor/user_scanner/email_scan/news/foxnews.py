import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.music_identity_contracts import outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://id.fox.com/status/v1/status"
    show_url = "https://foxnews.com"

    params = {
        'email': email
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
        'Accept': "*/*",
        'Accept-Encoding': "gzip, deflate, br, zstd",
        'x-api-key': "049f8b7844b84b9cb5f830f28f08648c",
        'origin': "https://auth.fox.com",
        'referer': "https://auth.fox.com/",
        'accept-language': "en-US,en;q=0.9"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params, headers=headers, follow_redirects=False)

            status, extra, reason = outcome(response, "foxnews", email)
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


async def validate_foxnews(email: str) -> Result:
    return await _check(email)
