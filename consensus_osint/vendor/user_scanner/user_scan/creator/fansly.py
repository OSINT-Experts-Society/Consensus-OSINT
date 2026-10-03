from urllib.parse import quote

from consensus_osint.core.fansly_contracts import result, valid_user
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_fansly(user: str) -> Result:
    show_url = f"https://fansly.com/{quote(user, safe='')}"
    if not valid_user(user):
        return Result.error("One Fansly username is required", url=show_url)
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    return generic_validate(
        "https://apiv2.fansly.com/api/v1/account", lambda response: result(response, user),
        show_url=show_url, headers=headers, params={"usernames": user}, follow_redirects=False,
    )
