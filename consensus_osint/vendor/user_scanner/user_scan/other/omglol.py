from urllib.parse import quote

from consensus_osint.core.omglol_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_omglol(user):
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://api.omg.lol/address/{encoded}/info", lambda response: result(response, user),
        show_url=f"https://omg.lol/{encoded}",
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}, follow_redirects=False,
    )
