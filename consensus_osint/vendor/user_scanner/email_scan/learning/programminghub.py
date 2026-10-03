import httpx

from consensus_osint.core.learning_validation_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api-prod.programminghub.io/v5/api/auth/recover/initiate"
    show_url = "https://play.google.com/store/apps/details?id=com.prghub.pro"

    payload = {
        "client": "android",
        "email": email
    }

    headers = {
        'User-Agent': "okhttp/5.3.2",
        'Accept-Encoding': "gzip",
        'client': "android",
        'locale': "en",
        'content-type': "application/json; charset=UTF-8"
    }

    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=15.0, follow_redirects=False)

            status, extra, reason = outcome(response, "programminghub", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_programminghub(email: str) -> Result:
    """
    Programming Hub email validator. Note: This will send a recovery email if it exists.
    """
    return await _check(email)
