from urllib.parse import quote

import httpx

from consensus_osint.core.learning_identity_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:

    url = f"https://api.allen-live.in/api/v1/user/identities/{quote(email, safe='')}"
    show_url = "https://allen.in"

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json",
        'Accept-Encoding': "identity",
        'x-client-type': "mweb",
        'Origin': "https://allen.in",
        'Referer': "https://allen.in/",
    }

    params = {
        'communicable': "true",
        'identity_type': "EMAIL"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params, headers=headers, follow_redirects=False)

            status, extra, reason = outcome(response, "allen", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(e)


async def validate_allen(email: str) -> Result:
    return await _check(email)
