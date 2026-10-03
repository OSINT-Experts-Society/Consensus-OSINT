from urllib.parse import quote

from consensus_osint.core.models import Status
from consensus_osint.core.other_email_contracts import outcome
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result


async def validate_start_me(email: str) -> Result:
    """Validate whether an email is registered on Start.me (start.me)."""
    url = f"https://start.me/users/check_email?email={quote(email, safe='')}"
    show_url = "https://start.me"
    headers = {
        "Accept": "application/json",
        "Referer": "https://start.me/users/sign_up",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        response = await impersonate_request_async(
            url,
            method="GET",
            headers=headers,
            impersonate="chrome",
            allow_redirects=False,
        )

        status, extra, reason = outcome(response, "start_me", email)
        if status is Status.FOUND:
            return Result.taken(url=show_url, extra=extra)
        if status is Status.NOT_FOUND:
            return Result.available(url=show_url)
        return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(f"Unexpected exception: {e}", url=show_url)
