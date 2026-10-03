import json

import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.music_identity_contracts import deezer_setup, outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://www.deezer.com"
    gw_url = "https://www.deezer.com/ajax/gw-light.php"

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
        'Accept-Encoding': "identity",
        'Content-Type': "text/plain;charset=UTF-8",
        'Origin': "https://account.deezer.com",
        'Referer': "https://account.deezer.com/"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            handshake_params = {
                'method': "deezer.getUserData",
                'input': "3",
                'api_version': "1.0",
                'api_token': ""
            }
            handshake_payload = {"APP_NAME": "Deezer"}

            r_handshake = await client.post(
                gw_url,
                params=handshake_params,
                content=json.dumps(handshake_payload),
                headers=headers, follow_redirects=False
            )

            api_token, reason = deezer_setup(r_handshake)
            if api_token is None:
                return Result.error(reason, url=show_url)

            validate_params = {
                'method': "user_checkRegisterConstraints",
                'input': "3",
                'api_version': "1.0",
                'api_token': api_token
            }

            validate_payload = {
                "APP_NAME": "Deezer",
                "EMAIL": email
            }

            response = await client.post(
                gw_url,
                params=validate_params,
                content=json.dumps(validate_payload),
                headers=headers, follow_redirects=False
            )

            status, extra, reason = outcome(response, "deezer", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url, extra=extra)
            return Result.error(reason, url=show_url)

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out! maybe region blocks")
    except Exception as e:
        return Result.error(e)


async def validate_deezer(email: str) -> Result:
    return await _check(email)
