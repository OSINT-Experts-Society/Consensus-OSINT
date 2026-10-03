import httpx

from consensus_osint.core.codecademy_contracts import outcome, setup
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://codecademy.com"
    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://www.codecademy.com/register?redirect=%2F',
        'Content-Type': 'application/json',
        'Origin': 'https://www.codecademy.com',
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            init_res = await client.get("https://www.codecademy.com/register", headers=headers)

            token, issue = setup(init_res)
            if issue is not None:
                return Result.error(issue[2], url=show_url)
            headers["X-CSRF-Token"] = token

            payload = {"user": {"email": email}}

            response = await client.post(
                'https://www.codecademy.com/register/validate',
                headers=headers,
                json=payload,
                follow_redirects=False,
            )

            status, _, reason = outcome(response)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(str(e))


async def validate_codecademy(email: str) -> Result:
    return await _check(email)
