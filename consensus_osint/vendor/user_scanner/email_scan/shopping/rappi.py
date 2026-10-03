import json
import re
import secrets
import time

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import email_flag_outcome, has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


def _generate_device_id() -> str:
    """Generate a random 16-character hex string for deviceid."""
    return secrets.token_hex(8)


def _generate_timestamp() -> str:
    """Generate current epoch timestamp in milliseconds."""
    return str(int(time.time() * 1000))


async def _check(email: str) -> Result:
    url_check = "https://services.rappi.com.ar/api/rocket/user/account/check-email"
    url_login = "https://services.rappi.com.ar/api/rocket/login/email/application_user"
    show_url = "https://www.rappi.com"

    device_id = _generate_device_id()
    ts = _generate_timestamp()

    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TP1A.220624.021)",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "user_id": "",
        "custom_country_code": "AR",
        "deviceid": device_id,
        "app-version": "88721",
        "app-version-name": "8.35.20260724-88721",
        "store-platform": "google",
        "amplitude-session-id": ts,
        "timestamp": ts,
        "request_timestamp": ts,
        "accept-language": "en-US",
        "language": "en",
        "country-code": "AR",
        "fp_dp_id": "3703578013",
        "content-type": "application/json; charset=UTF-8",
    }

    payload_check = {"email": email}

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.post(
                url_check, json=payload_check, headers=headers, timeout=6.0, follow_redirects=False
            )
            status, _, reason = email_flag_outcome(response, "exists", email)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            if status is not Status.FOUND:
                return Result.error(reason, url=show_url)

            from consensus_osint.adapters.user_scanner_adapter import notifications_allowed

            if not notifications_allowed():
                return Result.taken(url=show_url)

            # Optional notification-capable enrichment cannot overturn the lookup.
            extras = {}
            try:
                headers["timestamp"] = headers["request_timestamp"] = _generate_timestamp()
                response_login = await client.post(
                    url_login,
                    json={"email": email, "scope": "all"},
                    headers=headers,
                    timeout=6.0,
                    follow_redirects=False,
                )
                extras = _phone_metadata(response_login, email)
            except Exception:
                pass
            return Result.taken(url=show_url, extra=extras)

        except Exception as e:
            return Result.error(e, url=show_url)


def _phone_metadata(response, email: str) -> dict:
    # 401 is an expected login envelope here, not account evidence. Still apply
    # the same challenge/body checks before reading optional metadata.
    code = 400 if response.status_code == 401 else response.status_code
    issue, _ = http_issue(code, response.headers, response.text, accepted=(200, 400, 422))
    if issue is not None:
        return {}
    data = json.loads(response.text, object_pairs_hook=_unique_object)
    if not isinstance(data, dict):
        return {}
    err = data.get("error")
    if not isinstance(err, dict) or has_service_error({k: v for k, v in data.items() if k != "error"}):
        return {}
    if has_service_error(err):
        return {}
    for obj in (data, err):
        if "email" in obj and (not isinstance(obj["email"], str) or obj["email"].casefold() != email.casefold()):
            return {}
    phone = err.get("verification_value")
    kind = err.get("verification_type")
    if (
        not isinstance(phone, str)
        or not re.fullmatch(r"[+0-9*Xx(). -]{4,40}", phone)
        or not any(c.isdigit() for c in phone)
    ):
        return {}
    extras = {"phone": phone}
    if isinstance(kind, str) and re.fullmatch(r"[A-Za-z_ -]{1,40}", kind):
        extras["verification_type"] = kind
    return extras


async def validate_rappi(email: str) -> Result:
    """Check existence; optional login enrichment requires active scan permission."""
    return await _check(email)
