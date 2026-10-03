import json
import secrets

from consensus_osint.core.creator_email_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result


def _generate_trace_id() -> str:
    """Generates a 32-character hexadecimal string to emulate a real mobile tracing token."""
    return secrets.token_hex(16)

async def _check(email: str) -> Result:
    url = "https://kick.com/api/v1/signup/verify/email"
    show_url = "https://kick.com/"

    headers = {
        'User-Agent': "KickMobile/40.18.1 (com.kick.mobile; platform: android; build:60006868)",
        'Accept': "application/json",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/json",
        'cache-control': "no-store",
        'x-app-platform': "Android",
        'x-app-version': "40.18.1",
        'x-kick-app': "mobile",
        'x-req-trace': _generate_trace_id()
    }

    try:
        response = await impersonate_request_async(
            url, "POST", data=json.dumps({"email": email}), headers=headers, allow_redirects=False
        )

        # Check for generic perimeter blocks
        status, extra, reason = outcome(response, "kick", email)
        if status is Status.FOUND:
            return Result.taken(url=show_url, extra=extra)
        if status is Status.NOT_FOUND:
            return Result.available(url=show_url)
        return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(str(e))

async def validate_kick(email: str) -> Result:
    return await _check(email)
