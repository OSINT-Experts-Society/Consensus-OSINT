from consensus_osint.core.crm_contracts import crm_outcome
from consensus_osint.core.models import Status
import httpx
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://axonaut.com"
    headers = {
        'authority': 'axonaut.com',
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'referer': 'https://axonaut.com/en',
        'accept-language': 'en-US,en;q=0.9',
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.get(
                'https://axonaut.com/onboarding/',
                params={'email': email},
                headers=headers
            )

            status, reason = crm_outcome("axonaut", response, email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out", url=show_url)
    except Exception as exc:
        return Result.error(f"Lookup failed: {type(exc).__name__}", url=show_url)


async def validate_axonaut(email: str) -> Result:
    return await _check(email)
