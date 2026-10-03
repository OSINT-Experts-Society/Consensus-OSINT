import secrets
import uuid

import httpx

from consensus_osint.core.dating_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://api.skout.com/validations/Users_NewUserCheck"
    show_url = "https://www.skout.com"

    android_id = secrets.token_hex(8)
    app_id = f"{uuid.uuid4()}?identifier=skout.prod"
    gpsa_id = f"{uuid.uuid4()}?identifier=skout.prod"
    appset_id = f"{uuid.uuid4()}?identifier=skout.prod"
    firebase_id = secrets.token_hex(16)

    params = {
        "email": email,
        "name": "notSet",
        "brand": "skout",
    }

    headers = {
        "User-Agent": "Skout/23201 Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230901.001) 4.12.0",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "kissapi-ad-id": "c66aefe62fa926b6e76dc1ebef756baf",
        "kissapi-ad-name": "Organic",
        "kissapi-ad-label": "",
        "kissapi-app-version": "23201",
        "kissapi-version": "1.36.0",
        "kissapi-device-os": "33",
        "kissapi-device-model": "Pixel 6",
        "tz": "UTC",
        "kissapi-device": "android",
        "kissapi-app-package-id": "com.skout.android",
        "kissapi-brand": "skout",
        "kissapi-apptype": "google",
        "kissapi-android-id": android_id,
        "kissapi-app-id": app_id,
        "kissapi-gpsa-id": gpsa_id,
        "kissapi-gpsa-on": "true",
        "kissapi-appset-id": appset_id,
        "firebase-analytics-app-instance-id": firebase_id,
        "accept-language": "en-US",
        "wifi": "0",
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, params=params, headers=headers, timeout=6.0, follow_redirects=False)

            status, _, reason = outcome(response, "skout", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_skout(email: str) -> Result:
    """
    Skout dating app email validator.
    Checks Users_NewUserCheck endpoint.
    """
    return await _check(email)
