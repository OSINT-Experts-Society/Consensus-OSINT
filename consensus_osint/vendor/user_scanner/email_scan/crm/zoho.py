from urllib.parse import quote
from consensus_osint.core.crm_contracts import crm_outcome, http_problem
from consensus_osint.core.models import Status
import httpx
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://zoho.com"
    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Accept': '*/*',
        'Origin': 'https://accounts.zoho.com',
        'Referer': 'https://accounts.zoho.com/',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            setup = await client.get("https://accounts.zoho.com/signin", headers=headers)
            status, reason = http_problem(setup, html=True)
            if status is not None:
                return Result.error(reason, url=show_url)
            # The setup flow can set this cookie on a redirect response.
            # Check setup success first, then use this fresh client's cookie jar.
            csrf_cookie = client.cookies.get("iamcsr")

            if not csrf_cookie:
                return Result.error("CSRF cookie not found")

            headers['X-ZCSRF-TOKEN'] = f'iamcsrcoo={csrf_cookie}'

            payload = {
                'mode': 'primary',
                'servicename': 'ZohoCRM',
                'serviceurl': 'https://crm.zoho.com/crm/ShowHomePage.do',
                'service_language': 'en'
            }

            response = await client.post(
                f'https://accounts.zoho.com/signin/v2/lookup/{quote(email, safe="")}',
                headers=headers,
                data=payload
            )

            status, reason = crm_outcome("zoho", response, email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out", url=show_url)
    except Exception as exc:
        return Result.error(f"Lookup failed: {type(exc).__name__}", url=show_url)


async def validate_zoho(email: str) -> Result:
    return await _check(email)
