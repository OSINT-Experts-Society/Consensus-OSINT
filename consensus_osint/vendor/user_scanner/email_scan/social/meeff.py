import json
import random
import re
import string

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


def _generate_android_id() -> str:
    """Generate a random 16-character hex string representing an Android ID."""
    return "".join(random.choices(string.hexdigits.lower(), k=16))


async def _check(email: str) -> Result:
    url = "https://api.meeff.com/user/login/v4"
    show_url = "https://play.google.com/store/apps/details?id=com.noyesrun.meeff.kr"

    payload = {
        "provider": "email",
        "providerId": email,
        "providerToken": "",  # dummy password
        "os": "Android v11",
        "platform": "android",
        "device": "BRAND: VIVO, MODEL: VIVOY16, DEVICE: VIVOY16, PRODUCT: VIVOY16, DISPLAY: VIVOY!6_13_K.1098",
        "pushToken": "",
        "deviceUniqueId": _generate_android_id(),
        "deviceLanguage": "en",
        "deviceRegion": "US",
        "simRegion": "",
        "deviceGmtOffset": "+0530",
        "deviceRooted": 0,
        "deviceEmulator": 0,
        "appVersion": "7.1.2",
        "locale": "en",
    }

    headers = {
        "User-Agent": "okhttp/5.3.2",
        "Accept-Encoding": "gzip",
        "content-type": "application/json; charset=utf-8",
        "Cookie": "locale=en",
    }

    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=15.0, follow_redirects=False)

            # This endpoint uses 401 for its expected credential-error envelope.
            # Apply body/challenge guards even on that expected error status.
            code = 200 if response.status_code == 401 else response.status_code
            issue, reason = http_issue(code, response.headers, response.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            if response.status_code != 401:
                return Result.error("No supported login error response", url=show_url)
            data = json.loads(response.text, object_pairs_hook=_unique_object)
            if isinstance(data, dict):
                remainder = {k: v for k, v in data.items() if k != "errorMessage"}
                matching = all(
                    key not in data or isinstance(data[key], str) and data[key].casefold() == email.casefold()
                    for key in ("email", "providerId")
                )
                message = data.get("errorMessage")
                if (
                    matching
                    and data.get("success") is not True
                    and not has_service_error(remainder)
                    and isinstance(message, str)
                    and re.fullmatch(
                        r"(?:(?:this |the )?email(?: address)? )?hasn't been signed up yet[.!]?", message, re.I
                    )
                ):
                    return Result.available(url=show_url)
            # A password mismatch does not independently establish an account.
            return Result.error("Login response does not establish account status", url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_meeff(email: str) -> Result:
    """
    Meeff email validator. Checks login endpoint.
    """
    return await _check(email)
