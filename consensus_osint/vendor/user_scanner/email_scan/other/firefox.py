import json

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result

async def _check(email: str) -> Result:
    url = "https://api.accounts.firefox.com/v1/account/status"
    show_url = "https://firefox.com"

    payload = {
        "email": email
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, follow_redirects=False)

            if response.status_code == 403:
                return Result.error("Caught by WAF or IP Block (403)")

            if response.status_code == 429:
                return Result.error("Rate limited by Firefox (429)")

            if response.status_code != 200:
                return Result.error(f"HTTP Error: {response.status_code}")

            issue, reason = http_issue(response.status_code, response.headers, response.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            data = json.loads(response.text, object_pairs_hook=_unique_object)
            if not isinstance(data, dict) or has_service_error(data):
                return Result.error("Unexpected account-status response", url=show_url)
            if "email" in data and data["email"] != email:
                return Result.error("Conflicting account-status identity", url=show_url)
            if data.get("exists") is True:
                return Result.taken(url=show_url)

            elif data.get("exists") is False:
                return Result.available(url=show_url)

            return Result.error("Unexpected response body structure")

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out! maybe region blocks")
    except httpx.ReadTimeout:
        return Result.error("Server took too long to respond (Read Timeout)")
    except Exception as e:
        return Result.error(e)

async def validate_firefox(email: str) -> Result:
    return await _check(email)
