import httpx
import json
from consensus_osint.vendor.user_scanner.core.result import Result
from consensus_osint.core.jobs_learning_contracts import outcome
from consensus_osint.core.models import Status


async def _check(email: str) -> Result:
    url = "https://www.freelancer.com/api/users/0.1/users/check?compact=true&new_errors=true"
    show_url = "https://freelancer.com"

    payload = {
        "user": {
            "email": email
        }
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'Origin': 'https://www.freelancer.com',
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, content=json.dumps(payload), headers=headers)

            status, fields, reason = outcome('freelancer', response, email)
            if status is Status.FOUND:
                avatar = fields.pop('avatar', None)
                extra = {key: value for key, value in fields.items() if not isinstance(value, list)}
                return Result.taken(extra=extra, media={'avatar': avatar} if avatar else {}, url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason)
    except httpx.TimeoutException:
        return Result.error('Provider request timed out; account status is unknown.')
    except Exception:
        return Result.error('Provider request failed; account status is unknown.')


async def validate_freelancer(email: str) -> Result:
    return await _check(email)
