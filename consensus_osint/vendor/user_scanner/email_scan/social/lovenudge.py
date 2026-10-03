import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import email_flag_outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api.lovenudgeapp.com/api/register/check"
    show_url = "https://lovenudgeapp.com"

    params = {
        "email": email,
        "time_zone": "UTC",
        "app_version": "5.2.10",
    }

    headers = {
        "User-Agent": "okhttp/4.11.0",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.get(url, params=params, headers=headers, timeout=6.0, follow_redirects=False)

            status, _, reason = email_flag_outcome(response, "data", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_lovenudge(email: str) -> Result:
    """
    Love Nudge email validator. Checks register/check endpoint.
    """
    return await _check(email)
