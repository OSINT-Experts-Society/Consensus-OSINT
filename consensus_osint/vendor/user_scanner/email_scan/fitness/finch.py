import httpx
from consensus_osint.core.firebase_contracts import native_result
from consensus_osint.vendor.user_scanner.core.result import Result

async def _check(email: str) -> Result:
    url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode"
    show_url = "https://www.finchcare.com/"  # Standard user dashboard reference

    params = {
        'key': "AIzaSyAtxGf97SHuNfYC0pjpTM4FSwPf08n9VF0"
    }

    payload = {
        "requestType": 1,
        "email": email,
        "androidInstallApp": False,
        "canHandleCodeInApp": False,
        "clientType": "CLIENT_TYPE_ANDROID"
    }

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; RMX2193 Build/RP1A.200720.011)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/json",
        'X-Android-Package': "com.finch.finch",
        'Accept-Language': "en-US",
        'X-Client-Version': "Android/Fallback/X23002001/FirebaseCore-Android"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, params=params, json=payload, headers=headers)

            return native_result("reset", response, email, show_url)

    except Exception as e:
        return Result.error(str(e))

async def validate_finch(email: str) -> Result:
    return await _check(email)
