import json

from consensus_osint.core.creator_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.canva.com/_ajax/authnflow/user-authentication-methods"
    show_url = "https://www.canva.com/"

    headers = {
        "Referer": "https://www.canva.com/login",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }

    payload = {
        "C": "Linux / Chrome",
        "A?": "E",
        "L": email,
    }

    try:
        response = await impersonate_request_async(
            url, "POST", data=json.dumps(payload), headers=headers, impersonate="chrome120", allow_redirects=False
        )

        status, extra, reason = outcome(response, "canva", email)
        if status is Status.FOUND:
            return Result.taken(url=show_url, extra=extra)
        if status is Status.NOT_FOUND:
            return Result.available(url=show_url)
        return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(str(e))

async def validate_canva(email: str) -> Result:
    return await _check(email)
