from urllib.parse import quote

import httpx
from consensus_osint.core.provider_contracts import wordpress_lookup
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://wordpress.com"
    url = f'https://public-api.wordpress.com/rest/v1.1/users/{quote(email, safe="")}/auth-options'

    params = {
        'http_envelope': "1"
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'Accept': "application/json",
        'sec-ch-ua-platform': '"Linux"',
        'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
        'sec-ch-ua-mobile': "?0",
        'sec-fetch-site': "same-origin",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'referer': "https://public-api.wordpress.com/wp-admin/rest-proxy/?v=2.0",
        'accept-language': "en-US,en;q=0.9",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params, headers=headers)

            if response.headers.get("cf-mitigated", "").lower() == "challenge":
                return Result.error("Provider challenge; account status is unknown.", url=show_url)
            if response.status_code == 429:
                return Result.error("Rate limited by WordPress (429)", url=show_url)
            if response.status_code in (401, 403, 406, 407, 418, 451):
                return Result.error(f"Provider access blocked (HTTP {response.status_code})", url=show_url)
            if response.status_code != 200:
                return Result.error(f"WordPress API returned status {response.status_code}", url=show_url)
            exists, extra, reason = wordpress_lookup(response.json())
            if exists is True:
                return Result.taken(url=show_url, extra=extra)
            if exists is False:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out", url=show_url)
    except Exception as exc:
        return Result.error(f"WordPress lookup failed: {type(exc).__name__}", url=show_url)


async def validate_wordpress(email: str) -> Result:
    return await _check(email)
