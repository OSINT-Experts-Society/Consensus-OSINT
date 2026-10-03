import httpx

from consensus_osint.core.health_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://data.period-tracker.com/databackup/data.php"
    show_url = "https://period-tracker.com"

    params = {
        'action': "checkAccount"
    }

    payload = {
        'email': email,
        'app_type': "calendar",
        'app_platform': "android",
        'data_version': "33",
        'app_version': "12.7.6"
    }

    headers = {
        'User-Agent': "Dart/3.10 (dart:io)",
        'Accept-Encoding': "gzip"
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            # Form-encoded POST request
            response = await client.post(url, params=params, data=payload, headers=headers, timeout=6.0, follow_redirects=False)

            status, extra, reason = outcome(response, "myperiodtracker", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url, extra=extra)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_myperiodtracker(email: str) -> Result:
    """
    My Period Tracker email validator. Checks backup account existence endpoint.
    """
    return await _check(email)
