from urllib.parse import quote

from consensus_osint.core.faceit_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_faceit(user: str) -> Result:
    """Validate a player handle on Faceit (faceit.com)."""
    encoded = quote(user, safe="")
    return impersonate_validate(
        f"https://www.faceit.com/api/users/v1/nicknames/{encoded}",
        lambda response: result(response, user),
        headers={"Accept": "application/json"},
        show_url=f"https://www.faceit.com/en/players/{encoded}",
        impersonate="chrome",
        allow_redirects=False,
    )
