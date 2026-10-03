import secrets
import uuid

import httpx

from consensus_osint.core.dating_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api3.lespark.cn/login"
    show_url = "https://www.lespark.cn"

    req_id = str(uuid.uuid4())
    device_id = secrets.token_hex(8)
    gaid = str(uuid.uuid4())

    headers = {
        "User-Agent": "okhttp-okgo/jeasonlzy",
        "Accept-Encoding": "gzip",
        "accept-language": "en-US,en;q=0.8",
        "lang": "en",
        "lang-app": "en",
        "device-os": "13",
        "device_model": "Pixel 6",
        "bundle-id": "com.redwolfama.peonylespark.gp",
        "version": "9.7.38.1",
        "version-code": "786",
        "pkg": "com.redwolfama.peonylespark.gp",
        "device-id": device_id,
        "is-ipad": "0",
        "locale": "US",
        "is-cn": "0",
        "channel": "google",
        "request-id": req_id,
        "gaid": gaid,
    }

    payload = {
        "password": "d9bd8afc54ee5dc6c1ee6096e297ec31",
        "verion": "1",
        "email": email,
        "luid": "",
        "request-id": req_id,
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.post(url, data=payload, headers=headers, timeout=6.0, follow_redirects=False)

            status, _, reason = outcome(response, "lespark", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_lespark(email: str) -> Result:
    """
    LesPark dating app email validator.
    Checks login endpoint with dummy password.
    """
    return await _check(email)
