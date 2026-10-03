from urllib.parse import quote

from consensus_osint.core.picsart_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_picsart(user: str) -> Result:
    encoded = quote(user, safe="")
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    return generic_validate(
        f"https://api.picsart.com/users/show/{encoded}.json", lambda response: result(response, user),
        show_url=f"https://picsart.com/u/{encoded}", headers=headers, follow_redirects=False,
    )
