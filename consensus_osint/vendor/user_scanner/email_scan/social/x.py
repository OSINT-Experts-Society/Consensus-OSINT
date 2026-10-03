import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.twitter_email_contracts import outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email):
    url = "https://api.x.com/i/users/email_available.json"
    show_url = "https://x.com"
    params = {"email": email}
    headers = {
        "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36",
        "accept-encoding": "gzip, deflate, br, zstd",
        "sec-ch-ua-platform": "\"Android\"",
        "sec-ch-ua": "\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"",
        "x-twitter-client-language": "en",
        "sec-ch-ua-mobile": "?1",
        "x-twitter-active-user": "yes",
        "origin": "https://x.com",
        "priority": "u=1, i"
    }

    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            response = await client.get(url, params=params, headers=headers, follow_redirects=False)

            status, _, reason = outcome(response, email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e)


async def validate_x(email: str) -> Result:
    return await _check(email)
