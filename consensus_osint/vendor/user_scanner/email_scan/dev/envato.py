import httpx

from consensus_osint.core.dev_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://account.envato.com/api/public/validate_email"
    show_url = "https://elements.envato.com"

    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'Accept': "application/json",
        'Content-Type': "application/json",
        'x-client-version': "3.6.0",
        'origin': "https://elements.envato.com",
        'referer': "https://elements.envato.com/",
        'accept-language': "en-US,en;q=0.9",
    }

    payload = {
        "language_code": "en",
        "email": email
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers, follow_redirects=False)

            status, _, reason = outcome(response, "envato", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(f"Unexpected Exception: {e}")


async def validate_envato(email: str) -> Result:
    return await _check(email)
