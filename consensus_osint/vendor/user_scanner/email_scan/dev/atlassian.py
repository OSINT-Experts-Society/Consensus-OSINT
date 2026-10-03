import json

from consensus_osint.core.provider_contracts import atlassian_lookup

from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result


async def validate_atlassian(email: str) -> Result:
    """Validate whether an email is registered on Atlassian (Jira, Confluence, Bitbucket, Trello)."""
    url = "https://id.atlassian.com/rest/check-username"
    show_url = "https://id.atlassian.com"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Referer": "https://id.atlassian.com/login",
        "Accept-Language": "en-US,en;q=0.9",
    }
    payload = json.dumps({"username": email})

    try:
        response = await impersonate_request_async(
            url,
            method="POST",
            data=payload,
            headers=headers,
            impersonate="chrome",
        )

        if response.headers.get("cf-mitigated", "").lower() == "challenge":
            return Result.error("Provider challenge; account status is unknown.", url=show_url)

        if response.status_code in (401, 403, 406, 407, 418, 451):
            return Result.error(f"Provider access blocked (HTTP {response.status_code})", url=show_url)

        if response.status_code == 429:
            return Result.error("Rate limited by Atlassian (429)", url=show_url)

        if response.status_code != 200:
            return Result.error(f"Unexpected response status: {response.status_code}", url=show_url)

        exists, extra, reason = atlassian_lookup(response.json())
        if exists is True:
            return Result.taken(extra=extra, url=show_url)
        if exists is False:
            return Result.available(url=show_url)
        return Result.error(reason, extra=extra, url=show_url)

    except Exception as e:
        return Result.error(f"Lookup failed: {type(e).__name__}", url=show_url)
