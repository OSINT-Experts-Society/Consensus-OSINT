import httpx
import secrets
import string
from consensus_osint.vendor.user_scanner.core.result import Result
from consensus_osint.core.crm_contracts import http_problem
from consensus_osint.core.provider_contracts import has_service_error

def _generate_fingerprint(length: int = 20) -> str:
    """Generates a random alphanumeric device fingerprint matching the structural footprint."""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

async def _check(email: str) -> Result:
    url = "https://app.buymeacoffee.com/api/v1/email/login"
    show_url = "https://www.buymeacoffee.com/"

    # Preserving the native Android application headers and injecting a randomized fingerprint
    headers = {
        'User-Agent': "BuyMeaCoffee-Android-1.4.90",
        'Accept': "application/json, text/plain, */*",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/json",
        'x-device-fingerprint': _generate_fingerprint()
    }

    payload = {
        "email": email,
        "client_response": "",
        "captcha_version": "v3"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers)

            status, reason = http_problem(response, accepted=(200, 422))
            if status is not None:
                return Result.error(reason)
            try:
                data = response.json()
            except ValueError:
                return Result.error('Malformed provider JSON; account status is unknown.')
            if not isinstance(data, dict) or has_service_error(data):
                return Result.error('Unexpected or failed provider response; account status is unknown.')
            message = data.get('message')
            if message is not None and (not isinstance(message, str) or 'no account' in message.casefold()):
                return Result.error('Unrecognised or conflicting provider message; account status is unknown.')
            # Preserve the upstream-reported, typed login marker; this is not
            # independent live verification. The notification restriction stays.
            if response.status_code == 200 and data.get('otp_login') is True:
                return Result.taken(url=show_url)
            # HTTP 422 alone is input rejection, not an account-absence contract.
            # No exact provider-specific negative message is evidenced here.
            return Result.error('No supported account marker was returned; account status is unknown.')
    except httpx.TimeoutException:
        return Result.error('Provider request timed out; account status is unknown.')
    except Exception:
        return Result.error('Provider request failed; account status is unknown.')

async def validate_buymeacoffee(email: str) -> Result:
    return await _check(email)
