from consensus_osint.core.crm_contracts import crm_outcome
from consensus_osint.core.models import Status
import httpx
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://insightly.com"
    headers = {
        'authority': 'accounts.insightly.com',
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'x-requested-with': 'XMLHttpRequest',
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': 'https://accounts.insightly.com',
        'referer': 'https://accounts.insightly.com/?plan=trial',
        'accept-language': 'en-US,en;q=0.9',
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            payload = {'emailaddress': email}

            response = await client.post(
                'https://accounts.insightly.com/signup/isemailvalid',
                headers=headers,
                data=payload
            )

            status, reason = crm_outcome("insightly", response, email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out", url=show_url)
    except Exception as exc:
        return Result.error(f"Lookup failed: {type(exc).__name__}", url=show_url)


async def validate_insightly(email: str) -> Result:
    return await _check(email)
