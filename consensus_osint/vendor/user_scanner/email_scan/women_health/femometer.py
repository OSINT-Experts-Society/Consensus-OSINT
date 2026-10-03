import httpx

from consensus_osint.core.health_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api.femometer.com/v1/user_location"
    show_url = "https://www.femometer.com"

    params = {
        'country_code': "0",
        'phone_no': "0",
        'email': email,
        'app_flag': "1",
        'language': "2",
        'localTimezone': "UTC",
        'app_version': "5.43.5(4260)",
        'platform_type': "1",
        'isGooglePlay': "true"
    }

    headers = {
        'User-Agent': "okhttp/4.12.0",
        'Accept-Encoding': "gzip",
        'content-type': "application/json; charset=utf-8"
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.get(url, params=params, headers=headers, timeout=6.0, follow_redirects=False)

            status, extra, reason = outcome(response, "femometer", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url, extra=extra)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_femometer(email: str) -> Result:
    """
    Femometer email validator. Checks user location endpoint for account existence.
    """
    return await _check(email)
