import json
import secrets

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://sdk.weverse.io/api/v1/auth/password-reset/otp-sessions"
    show_url = "https://weverse.io"

    payload = {
        "email": email
    }

    device_id = secrets.token_hex(15)
    trace_id = secrets.token_hex(16).upper()

    headers = {
        "User-Agent": "AppName/weverse AppVersion/4.5.0 BundleId/co.benx.weverse OS/Android SystemVersion/Android13 DeviceModel/Pixel 6",
        "Accept-Encoding": "gzip",
        "x-sdk-language": "en",
        "x-clog-producer": "account-android",
        "x-sdk-service-secret": "9d79660be5ca452ab8c93bcaee310bb7",
        "x-clog-user-device-id": device_id,
        "x-sdk-platform": "Android",
        "x-sdk-device-model": "Pixel 6",
        "x-sdk-app-version": "3.17.0",
        "x-sdk-platform-version": "13",
        "x-sdk-service-id": "weverse",
        "x-sdk-trace-id": trace_id,
        "x-sdk-version": "4.5.0",
        "content-type": "application/json; charset=UTF-8",
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=6.0, follow_redirects=False)

            issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 404))
            if issue is not None:
                return Result.error(reason, url=show_url)
            data = json.loads(response.text, object_pairs_hook=_unique_object)
            if not isinstance(data, dict) or has_service_error(data):
                return Result.error("Invalid or failed account lookup", url=show_url)
            for key in ("email", "userid"):
                if key in data and (not isinstance(data[key], str) or data[key].casefold() != email.casefold()):
                    return Result.error("Account lookup returned a different email", url=show_url)

            if response.status_code == 200:
                return Result.error("A password-reset OTP session does not establish account existence", url=show_url)

            if response.status_code == 404:
                msg = data.get("message")
                if isinstance(msg, str) and msg.casefold() in ("account does not exist", "account does not exist."):
                    return Result.available(url=show_url)

            return Result.error(
                f"Unexpected response status: {response.status_code}, report it via GitHub issues",
                url=show_url,
            )

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_weverse(email: str) -> Result:
    """
    Weverse email validator. Checks password-reset/otp-sessions endpoint.
    Loud module because creating an OTP session sends a reset code.
    """
    return await _check(email)
