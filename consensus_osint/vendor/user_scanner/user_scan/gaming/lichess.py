from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_lichess(user):
    encoded = quote(user, safe="")
    url = "https://lichess.org/api/user/" + encoded
    show_url = "https://lichess.org/@/" + encoded
    return generic_validate(
        url, lambda response: result(response, "lichess", user),
        show_url=show_url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
