import httpx
from consensus_osint.core.firebase_contracts import native_result
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword"
    show_url = "https://play.google.com/store/apps/details?id=pl.lifebite.iyoni"

    params = {
        'key': "AIzaSyCBpmgku8MoHzusfTQlPwMcUObhPGUHc-w"
    }

    payload = {
        "email": email,
        "password": "generic_password_123",
        "returnSecureToken": True,
        "clientType": "CLIENT_TYPE_ANDROID"
    }

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TP1A.220624.021)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/json",
        'X-Android-Package': "pl.lifebite.iyoni",
        'Accept-Language': "en-US"
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.post(url, params=params, json=payload, headers=headers, timeout=6.0)

            return native_result("password", response, email, show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_iyoni(email: str) -> Result:
    """
    Iyoni email validator. Checks Firebase Auth verifyPassword endpoint.
    """
    return await _check(email)
