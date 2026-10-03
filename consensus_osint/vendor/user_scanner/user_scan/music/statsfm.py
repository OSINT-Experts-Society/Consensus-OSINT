from urllib.parse import quote

from consensus_osint.core.statsfm_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_statsfm(user: str) -> Result:
    encoded = quote(user, safe="")
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    return generic_validate(
        f"https://api.stats.fm/api/v1/users/{encoded}", lambda response: result(response, user),
        show_url=f"https://stats.fm/{encoded}", headers=headers, follow_redirects=False,
    )
