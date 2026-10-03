import httpx

from consensus_osint.core.learning_identity_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://app.aslbloom.com/api/searchForUser"
    show_url = "https://www.aslbloom.com"

    headers = {
        "User-Agent": "okhttp/4.12.0",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
    }

    payload = {
        "email": email,
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, follow_redirects=False)

            status, extra, reason = outcome(response, "aslbloom", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_aslbloom(email: str) -> Result:
    """
    ASL Bloom email validator.
    Checks searchForUser API endpoint.
    """
    return await _check(email)
