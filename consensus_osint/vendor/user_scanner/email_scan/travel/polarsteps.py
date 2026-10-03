import httpx
import secrets
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.polarsteps.com/api/users/validation/unique"
    show_url = "https://polarsteps.com"

    payload = {
        'field': "email",
        'value': email
    }

    device_id = secrets.token_hex(8)

    headers = {
        'User-Agent': "Polarsteps/10.6.0 (com.polarsteps; build:2000010449; Android 33)",
        'Accept-Encoding': "gzip",
        'polarsteps-api-version': "73",
        'polarsteps-user-language': "en-US",
        'polarsteps-app-version-code': "2000010449",
        'polarsteps-app-version': "10.6.0",
        'polarsteps-device-platform': "1",
        'Accept-Language': "en-US",
        'polarsteps-device-id': device_id,
        'polarsteps-device-name': "Samsung%20SM-G973F"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, data=payload, headers=headers)

            if response.status_code != 200:
                return Result.error(f"HTTP {response.status_code}")

            try:
                data = response.json()
            except Exception:
                return Result.error(f"Unexpected: {response.text[:20]}")

            if isinstance(data, dict) and type(data.get("is_unique")) is bool:
                if data["is_unique"]:
                    return Result.available(url=show_url)
                return Result.taken(url=show_url)

            return Result.error("Response did not contain a boolean is_unique field")

    except Exception as e:
        return Result.error(e)


async def validate_polarsteps(email: str) -> Result:
    return await _check(email)
