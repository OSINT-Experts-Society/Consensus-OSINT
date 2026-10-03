import httpx
from consensus_osint.core.firebase_contracts import native_result
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode"
    show_url = "https://play.google.com/store/apps/details?id=com.bunpoapp"

    params = {
        'key': "AIzaSyAxg8aXqILmTAN_OOAGIRt0IL6nkQyj3p8"
    }

    payload = {
        "requestType": 1,
        "email": email,
        "androidInstallApp": False,
        "canHandleCodeInApp": False,
        "clientType": "CLIENT_TYPE_ANDROID"
    }

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TP1A.220624.021)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/json",
        'X-Android-Package': "com.bunpoapp",
        'Accept-Language': "en-, en-US",
        'X-Client-Version': "Android/Fallback/X23000000/FirebaseCore-Android"
    }

    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            response = await client.post(url, params=params, json=payload, headers=headers, timeout=15.0)

            return native_result("reset", response, email, show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_bunpo(email: str) -> Result:
    """
    Bunpo email validator. Note: This will send a password reset email if it exists.
    """
    return await _check(email)
