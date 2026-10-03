import httpx
from consensus_osint.core.firebase_contracts import native_result
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri"
    show_url = "https://justwatch.com"
    params = {
        'key': "AIzaSyDv6JIzdDvbTBS-JWdR4Kl22UvgWGAyuo8"
    }
    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
        'Content-Type': "application/json",
        'x-client-version': "Chrome/JsCore/10.14.1/FirebaseCore-web",
        'origin': "https://www.justwatch.com",
        'referer': "https://www.justwatch.com/",
    }
    payload = {
        "identifier": email,
        "continueUri": "https://www.justwatch.com/"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                url,
                params=params,
                json=payload,
                headers=headers
            )

            return native_result("auth", response, email, show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(f"Unexpected Exception: {e}")


async def validate_justwatch(email: str) -> Result:
    return await _check(email)
