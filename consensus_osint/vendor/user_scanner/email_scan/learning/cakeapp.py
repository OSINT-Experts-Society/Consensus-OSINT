import httpx

from consensus_osint.core.learning_validation_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api.cakeapp.me/gw/auth/email/validate"
    show_url = "https://play.google.com/store/apps/details?id=me.mycake"

    params = {
        'timezone': "330",
        'lang': "en",
        'languageToLearn': "en",
        'appVersion': "6.8.0",
        'os': "android",
        'osVersion': "11",
        'email': email
    }

    headers = {
        'User-Agent': "okhttp/4.12.0",
        'Accept-Encoding': "gzip"
    }

    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            response = await client.get(url, params=params, headers=headers, timeout=15.0, follow_redirects=False)

            status, extra, reason = outcome(response, "cakeapp", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_cakeapp(email: str) -> Result:
    """
    Cake App email validator. Checks email validation endpoint without sending an email.
    """
    return await _check(email)
