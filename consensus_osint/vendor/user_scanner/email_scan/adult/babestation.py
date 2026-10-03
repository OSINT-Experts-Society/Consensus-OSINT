import httpx

from consensus_osint.core.adult_email_contracts import user_scanner_outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.babestation.tv/user/send/username-reminder"
    show_url = "https://babestation.tv"

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json, text/plain, */*",
        'Content-Type': "application/json",
        'x-requested-with': "XMLHttpRequest",
        'origin': "https://www.babestation.tv",
        'referer': "https://www.babestation.tv/forgot-password-or-username",
        'accept-language': "en-US,en;q=0.9",
    }

    payload = {
        "email": email
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers, follow_redirects=False)
            status, _, reason = user_scanner_outcome(response, "babestation", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(f"Unexpected Exception: {e}")


async def validate_babestation(email: str) -> Result:
    return await _check(email)
