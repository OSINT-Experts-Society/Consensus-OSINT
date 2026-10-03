import json
import secrets
import time
import uuid

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


def _generate_device_id() -> str:
    """Generate a random UUID v4 string with R suffix for amplitude device_id."""
    return f"{uuid.uuid4()}R"


def _generate_app_instance_id() -> str:
    """Generate a random 32-character hex string for Google Analytics app_instance_id."""
    return secrets.token_hex(16)


def _generate_timestamp() -> int:
    """Generate current epoch timestamp in milliseconds."""
    return int(time.time() * 1000)


async def _check(email: str) -> Result:
    url = "https://api.locketcamera.com/validateEmailAddress"
    show_url = "https://locketcamera.com"

    payload = {
        "data": {
            "analytics": {
                "amplitude": {"device_id": _generate_device_id(), "session_id": _generate_timestamp()},
                "experiments": {
                    "android_flag_2": 800,
                    "android_flag_1": 0,
                    "android_flag_9": 0,
                    "android_flag_8": 807,
                    "android_flag_7": 200,
                    "android_flag_6": 200,
                    "android_flag_5": 403,
                    "android_flag_4": 0,
                    "android_flag_10": 0,
                    "android_flag_3": 0,
                },
                "google_analytics": {"app_instance_id": _generate_app_instance_id()},
                "android_version": "1.234.2",
                "android_build": "577",
                "platform": "android",
            },
            "operation": "sign_in",
            "email": email,
        }
    }

    headers = {
        "User-Agent": "okhttp/4.12.0",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/json; charset=utf-8",
    }

    async with httpx.AsyncClient(http2=True) as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=6.0, follow_redirects=False)

            status, _, reason = _outcome(response, email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_locket(email: str) -> Result:
    """
    Locket Widget email validator. Checks validateEmailAddress endpoint.
    """
    return await _check(email)


def _outcome(response, email):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No coherent Locket email-validation result")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (ValueError, TypeError):
        return unknown
    if not isinstance(data, dict) or has_service_error(data):
        return unknown
    result = data.get("result")
    if not isinstance(result, dict):
        return unknown
    for record in (data, result):
        if "email" in record and (
            not isinstance(record["email"], str) or record["email"].casefold() != email.casefold()
        ):
            return unknown
    code = result.get("status")
    if type(code) is not int:
        return unknown
    if code == 200 and result.get("needs_registration") is False and not has_service_error(result):
        return Status.FOUND, {}, None
    # Keep the explicit missing-account code; arbitrary error fragments do not
    # identify which object is missing. Conflicting registration flags invalidate it.
    if code == 601 and ("needs_registration" not in result or result["needs_registration"] is True):
        remainder = {k: v for k, v in result.items() if k != "error"}
        error = result.get("error")
        if not has_service_error(remainder) and (error in (None, "") or error == "Email does not exist"):
            return Status.NOT_FOUND, {}, None
    return unknown
