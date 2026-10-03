import json

from consensus_osint.core.creator_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.patreon.com/api/auth"
    show_url = "https://patreon.com"

    params = {
        'include': "user.null",
        'fields[user]': "[]",
        'json-api-version': "1.0",
        'json-api-use-default-includes': "false"
    }

    payload = json.dumps({
        "data": {
            "type": "genericPatreonApi",
            "attributes": {
                "patreon_auth": {"email": email, "allow_account_creation": False},
                "auth_context": "auth",
                "ru": "https://www.patreon.com/home",
            },
            "relationships": {},
        }
    })

    headers = {
        'Accept-Encoding': "gzip, deflate, br, zstd",
        'content-type': "application/vnd.api+json",
        'sec-gpc': "1",
        'accept-language': "en-US,en;q=0.7",
        'origin': "https://www.patreon.com",
        'sec-fetch-site': "same-origin",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'referer': "https://www.patreon.com/login"
    }

    try:
        response = await impersonate_request_async(
            url, "POST", params=params, data=payload, headers=headers, allow_redirects=False
        )

        status, extra, reason = outcome(response, "patreon", email)
        if status is Status.FOUND:
            return Result.taken(url=show_url, extra=extra)
        if status is Status.NOT_FOUND:
            return Result.available(url=show_url)
        return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(f"unexpected exception: {e}")


async def validate_patreon(email: str) -> Result:
    return await _check(email)
