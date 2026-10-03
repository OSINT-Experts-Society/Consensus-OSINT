import random
import string

import httpx

from consensus_osint.core.adult_email_contracts import user_scanner_outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


def _generate_device_no() -> str:
    """Generate a random 33-character hex string representing a device number."""
    return "".join(random.choices("0123456789abcdef", k=33))


def _generate_ssid() -> str:
    """Generate a random 19-character numeric string representing an SSID."""
    return "".join(random.choices(string.digits, k=19))


async def _check(email: str) -> Result:
    url = "https://api.fantachat.ai/user/send/auth/code"
    show_url = "https://play.google.com/store/apps/details?id=com.api.fantachat"

    payload = {
        "email": email,
        "methodType": 2
    }

    device_no = _generate_device_no()
    ssid = _generate_ssid()

    headers = {
        'User-Agent': "okhttp/4.12.0",
        'Accept': "application/json, text/plain, */*",
        'Accept-Encoding': "gzip",
        'x-system-region': "US",
        'sim-state': "EMPTY",
        'vpn-on': "true",
        'ssid': ssid,
        'device-model': "Pixel 6",
        'accept-language': "en",
        'x-app-name': "Fantasia",
        'timezone': "GMT+0",
        'source-platform': "Android",
        'app-version': "255",
        'app-version-code': "255",
        'device-no': device_no,
        'fingerprint': device_no,
        'authtoken': "",
        'content-type': "application/json; charset=UTF-8"
    }

    async with httpx.AsyncClient(timeout=20.0, http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=20.0, follow_redirects=False)
            status, _, reason = user_scanner_outcome(response, "fantasia", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_fantasia(email: str) -> Result:
    """
    Fantasia email validator. Note: This will send an auth code email if it exists.
    """
    return await _check(email)
