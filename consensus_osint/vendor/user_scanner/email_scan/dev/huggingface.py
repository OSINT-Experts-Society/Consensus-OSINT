import httpx

from consensus_osint.core.dev_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://huggingface.co/api/check-user-email"
    show_url = "https://huggingface.co"
    payload = {'email': email}

    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        'Accept-Encoding': "identity",
        'referer': "https://huggingface.co/join",
    }

    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=15.0, follow_redirects=False)
            status, _, reason = outcome(response, "huggingface", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e)


async def validate_huggingface(email: str) -> Result:
    return await _check(email)
