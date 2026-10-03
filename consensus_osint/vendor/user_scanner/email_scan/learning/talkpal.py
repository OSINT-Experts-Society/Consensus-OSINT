import httpx

from consensus_osint.core.learning_validation_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api.talkpal.ai/api/v1/auth/recovery-request"
    show_url = "https://talkpal.ai"

    payload = {
        "email": email,
        "source": "app"
    }

    headers = {
        'User-Agent': "NitroFetch/1.0",
        'Accept': "application/json, text/plain, */*",
        'Content-Type': "application/json",
        'source': "app",
        'source-device': "ANDROID",
        'priority': "u=1, i"
    }

    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=15.0, follow_redirects=False)

            status, extra, reason = outcome(response, "talkpal", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_talkpal(email: str) -> Result:
    """
    TalkPal email validator. Note: This will send a password reset email if it exists.
    """
    return await _check(email)
