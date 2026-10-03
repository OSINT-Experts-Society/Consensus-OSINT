from urllib.parse import quote

from consensus_osint.core.sportstracker_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_sportstracker(user):
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://api.sports-tracker.com/apiserver/v1/user/name/{encoded}", lambda response: result(response, user),
        show_url=f"https://www.sports-tracker.com/view_profile/{encoded}",
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        follow_redirects=False,
    )
