import httpx

from consensus_osint.core.learning_validation_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://v2.heyjapan.net/password/passwordCode"
    show_url = "https://heyjapan.net"

    payload = {
        "email": email
    }

    headers = {
        'User-Agent': "okhttp/5.3.2",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/json"
    }

    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=15.0, follow_redirects=False)

            status, extra, reason = outcome(response, "heyjapan", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_heyjapan(email: str) -> Result:
    """
    HeyJapan email validator. Note: This will send a restore code via email if it exists.
    """
    return await _check(email)
