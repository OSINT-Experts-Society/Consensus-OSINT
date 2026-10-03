import httpx

from consensus_osint.core.health_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://proactiveapp.com/account/login_native_v1"
    show_url = "https://womanlog.com"

    payload = {
        "email": email,
        "password": "dummy_password_xyz123",
        "package": "com.womanlog",
        "app_version": "7.3.5",
        "os": "A",
    }

    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; WayDroid x86_64 Device Build/TQ3A.230901.001)",
        "Accept-Encoding": "gzip",
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.post(url, data=payload, headers=headers, timeout=6.0, follow_redirects=False)

            status, extra, reason = outcome(response, "womanlog", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url, extra=extra)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_womanlog(email: str) -> Result:
    """
    WomanLog (ProactiveApp) email validator.
    Checks login_native_v1 endpoint with form data.
    """
    return await _check(email)
