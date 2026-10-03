import json
import time

import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import email_flag_outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.pinterest.com/resource/ApiResource/get/"
    show_url = "https://pinterest.com"

    data_str = json.dumps({
        "options": {
            "url": "/v3/register/exists/",
            "data": {"email": email}
        },
        "context": {}
    }, separators=(',', ':'))

    params = {
        'source_url': "/signup/step1/",
        'data': data_str,
        '_': str(int(time.time() * 1000))
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json, text/javascript, */*, q=0.01",
        'Accept-Language': "en-US,en;q=0.9",
        'x-pinterest-pws-handler': "www/signup/[step].js",
        'x-app-version': "2503cde",
        'x-requested-with': "XMLHttpRequest",
        'x-pinterest-source-url': "/signup/step1/",
        'x-pinterest-appstate': "active",
        'origin': "https://www.pinterest.com",
        'referer': "https://www.pinterest.com/",
        'sec-fetch-site': "same-origin",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'priority': "u=1, i"
    }

    try:

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params, headers=headers, follow_redirects=False)

            status, _, reason = email_flag_outcome(response, "data", email, path=("resource_response",))
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(f"Unexpected Exception: {e}")


async def validate_pinterest(email: str) -> Result:
    return await _check(email)
