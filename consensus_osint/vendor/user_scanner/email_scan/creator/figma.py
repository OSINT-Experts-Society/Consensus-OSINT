import urllib.parse

from consensus_osint.core.creator_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    encoded_email = urllib.parse.quote(email)
    url = f"https://www.figma.com/api/session/available_auth_methods?email={encoded_email}&form_intent=sign_up"
    show_url = "https://www.figma.com/"

    headers = {
        "Referer": "https://www.figma.com/signup",
        "Accept": "application/json, text/plain, */*",
    }

    try:
        response = await impersonate_request_async(
            url, "GET", headers=headers, impersonate="chrome120", allow_redirects=False
        )

        status, extra, reason = outcome(response, "figma", email)
        if status is Status.FOUND:
            return Result.taken(url=show_url, extra=extra)
        if status is Status.NOT_FOUND:
            return Result.available(url=show_url)
        return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(str(e))

async def validate_figma(email: str) -> Result:
    return await _check(email)
