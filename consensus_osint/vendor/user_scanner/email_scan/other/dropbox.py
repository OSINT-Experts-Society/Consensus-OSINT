import httpx

from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.models import Status
from consensus_osint.core.other_email_contracts import outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    """
    Checks whether a given email is registered on Dropbox.

    The check has two steps:

    1. Retrieve CSRF token (is set as a cookie with name "t").
    2. Use the check_user_with_email_exists endpoint of Dropbox's API to retreive the result.

    The API also returns whether the given email is registered as a recovery email and whether it has a passkey.
    """

    show_url = "https://www.dropbox.com"
    check_user_url = f"{show_url}/2/account/check_user_with_email_exists"

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0",
        "Referer": show_url,
        "Origin": show_url,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        # 1. Retrieve the CSRF token
        csrf_token_retrieval_response = await client.get(show_url, headers=headers, follow_redirects=False)

        issue, reason = http_issue(
            csrf_token_retrieval_response.status_code,
            csrf_token_retrieval_response.headers,
            csrf_token_retrieval_response.text,
        )
        if issue is not None:
            return Result.error(reason, url=show_url)

        # Dropbox sets the CSRF token as the "t" cookie. The same value is also mirrored in "__Host-js_csrf".
        csrf_token = client.cookies.get("t")
        if not valid_token(csrf_token):
            return Result.error("CSRF token not retrieved")

        # 2. Retrieve the information from Dropbox's API
        headers["X-CSRF-Token"] = csrf_token
        payload = {"email": email}
        response = await client.post(check_user_url, headers=headers, json=payload, follow_redirects=False)

    status, extra, reason = outcome(response, "dropbox", email)
    if status is Status.FOUND:
        return Result.taken(url=show_url, extra=extra)
    if status is Status.NOT_FOUND:
        return Result.available(url=show_url)
    return Result.error(reason, url=show_url)


async def validate_dropbox(email: str) -> Result:
    return await _check(email)
