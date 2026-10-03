import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.shopping_validation_contracts import outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api.tatadigital.com/api/v2/sso/check-email"
    show_url = "https://tatadigital.com"

    payload = {
        "email": email,
        "sendOtp": False,
    }

    headers = {
        "User-Agent": "okhttp/5.2.0",
        "Accept-Encoding": "gzip",
        "client_id": "TATACLIQ-ANDROID-APP",
        "appversion": "103.22.0",
        "appplatform": "android",
        "content-type": "application/json; charset=UTF-8",
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=6.0, follow_redirects=False)

            status,extra,reason=outcome(response,"tatacliq",email)
            if status is Status.FOUND:
                return Result.taken(url=show_url,extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url,extra=extra)
            return Result.error(reason,url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_tatacliq(email: str) -> Result:
    """
    Tata CLiQ (Tata Neu / Tata Digital SSO) email validator.
    Checks check-email endpoint without sending OTP (sendOtp=False).
    """
    return await _check(email)
