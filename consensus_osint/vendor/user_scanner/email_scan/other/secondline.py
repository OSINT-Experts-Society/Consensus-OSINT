import uuid

import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.other_email_contracts import outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://autobizline.com/secondline/user/has_user/"
    show_url = "https://autobizline.com"

    headers = {
        "User-Agent": "okhttp/4.10.0",
        "Accept-Encoding": "gzip",
    }

    payload = {
        "api_token": "S(FNMSLDFKSD)FLKSlsdflkladf09asdfsafdasdf90123iksf=!@*#",
        "from_channel": "android",
        "device_id": str(uuid.uuid4()),
        "user_number": email,
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, data=payload, headers=headers, timeout=6.0, follow_redirects=False)

            status, extra, reason = outcome(response, "secondline", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_secondline(email: str) -> Result:
    """
    SecondLine email validator.
    Checks user/has_user API endpoint.
    """
    return await _check(email)
