from urllib.parse import quote

import httpx

from consensus_osint.core.learning_validation_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = f"https://api.classdojo.com/api/user/emailValidation/{quote(email, safe='')}"
    show_url = "https://www.classdojo.com"

    params = {
        "skipDomainValidation": "false",
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; WayDroid x86_64 Device Build/TQ3A.230901.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/111.0.5563.116 Safari/537.36",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "x-client-identifier": "Android",
        "x-client-version": "8.80.0",
        "x-sign-attachment-urls": "true",
        "x-client-os-version": "33",
        "x-device-id": "fb125fbaf088ff2d",
        "x-client-language": "en-US",
        "accept-language": "en",
        "x-rn-request": "true",
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.get(url, params=params, headers=headers, timeout=6.0, follow_redirects=False)

            status, extra, reason = outcome(response, "classdojo", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_classdojo(email: str) -> Result:
    """
    ClassDojo learning app email validator.
    Checks emailValidation endpoint and extracts metadata into extra.
    """
    return await _check(email)
