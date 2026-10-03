import json

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api.couplejoyapp.com/v1/reset-password"
    show_url = "https://couplejoyapp.com"

    payload = {"email": email}

    headers = {
        "User-Agent": "okhttp/4.12.0",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/json",
        "app-language": "en",
        "app-timezone": "UTC",
        "app-platform": "android",
        "app-version": "4.28.0",
        "app-locale": "en-US",
        "app-os-version": "11",
        "authorization": "Bearer null",
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=6.0, follow_redirects=False)

            issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 400))
            if issue is not None:
                return Result.error(reason, url=show_url)
            data = json.loads(response.text, object_pairs_hook=_unique_object)
            if isinstance(data, dict):
                matching = "email" not in data or (
                    isinstance(data["email"], str) and data["email"].casefold() == email.casefold()
                )
                # A reset acknowledgment does not establish whether an account exists.
                # Preserve only the explicit missing-address error on its expected status.
                remainder = {k: v for k, v in data.items() if k != "success"}
                if (
                    response.status_code == 400
                    and matching
                    and data.get("code") == "EMAIL_NOT_FOUND"
                    and ("success" not in data or data["success"] is False)
                    and not has_service_error(remainder)
                ):
                    return Result.available(url=show_url)
            return Result.error("Recovery response does not establish account status", url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_couplejoy(email: str) -> Result:
    """
    Couplejoy email validator. Checks reset-password endpoint.
    Loud module because it sends password reset email when account exists.
    """
    return await _check(email)
