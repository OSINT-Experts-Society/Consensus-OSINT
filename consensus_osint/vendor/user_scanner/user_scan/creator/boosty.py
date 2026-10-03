from urllib.parse import quote

from consensus_osint.core.boosty_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_boosty(user: str) -> Result:
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://api.boosty.to/v1/blog/{encoded}",
        lambda response: result(response, user),
        show_url=f"https://boosty.to/{encoded}", follow_redirects=False,
    )
