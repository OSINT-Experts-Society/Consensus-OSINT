from consensus_osint.core.crm_contracts import crm_outcome
from consensus_osint.core.models import Status
import httpx
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://hubspot.com"
    headers = {
        'authority': 'api.hubspot.com',
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'content-type': 'application/json',
        'origin': 'https://app.hubspot.com',
        'referer': 'https://app.hubspot.com/',
        'accept-language': 'en-US,en;q=0.9',
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            payload = {
                "email": email,
                "password": "",
                "rememberLogin": False
            }

            response = await client.post(
                'https://api.hubspot.com/login-api/v1/login',
                headers=headers,
                json=payload
            )

            status, reason = crm_outcome("hubspot", response, email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out", url=show_url)
    except Exception as exc:
        return Result.error(f"Lookup failed: {type(exc).__name__}", url=show_url)


async def validate_hubspot(email: str) -> Result:
    return await _check(email)
