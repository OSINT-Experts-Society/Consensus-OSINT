import httpx
import json
from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import email_flag_outcome
from consensus_osint.vendor.user_scanner.core.result import Result

async def _check(email: str) -> Result:
    url = "https://sm-prod2.any.do/check_email"
    show_url = "https://any.do"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "*/*",
        "Content-Type": "application/json; charset=UTF-8",
        "Origin": "https://desktop.any.do",
        "Referer": "https://desktop.any.do/",
    }

    payload = {
        "email": email
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                url,
                content=json.dumps(payload),
                headers=headers
            )

            status, _, reason = email_flag_outcome(response, "user_exists", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out! maybe region blocks")
    except httpx.ReadTimeout:
        return Result.error("Server took too long to respond (Read Timeout)")
    except Exception as e:
        return Result.error(e)

async def validate_anydo(email: str) -> Result:
    return await _check(email)
