import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import literal_email_outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.plurk.com/Users/isEmailFound"
    show_url = "https://www.plurk.com"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://www.plurk.com",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                url,
                headers=headers,
                data={"email": email},
                follow_redirects=False,
            )

        status, _, reason = literal_email_outcome(response, "True", "False")
        if status is Status.FOUND:
            return Result.taken(url=show_url)
        if status is Status.NOT_FOUND:
            return Result.available(url=show_url)
        return Result.error(reason, url=show_url)

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out")

    except httpx.ReadTimeout:
        return Result.error("Server took too long to respond")

    except Exception as e:
        return Result.error(e)


async def validate_plurk(email: str) -> Result:
    return await _check(email)
