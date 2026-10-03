from urllib.parse import quote

import httpx

from consensus_osint.core.autodiscover import routing_fields
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    base_url = "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/"
    show_url = "https://office365.com"
    headers = {
        "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro)",
        "Accept": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.get(base_url + quote(email, safe=""),
                                        params={"Protocol": "Autodiscoverv1"}, headers=headers)
        if response.status_code != 200:
            return Result.error(f"Autodiscover request returned HTTP {response.status_code}; mailbox state is unknown", url=show_url)
        fields = routing_fields(response)
        if fields is None:
            return Result.error("Unrecognised Autodiscover routing response; mailbox state is unknown", url=show_url)
        return Result.taken("Autodiscover route returned; not proof of mailbox existence or ownership",
                            url=show_url, extra=fields)
    except Exception as exc:
        return Result.error(exc)


async def validate_office365(email: str) -> Result:
    return await _check(email)
