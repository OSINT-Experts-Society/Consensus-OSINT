from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_modrinth(user):
    encoded = quote(user, safe="")
    url = "https://api.modrinth.com/v2/user/" + encoded
    show_url = "https://modrinth.com/user/" + encoded
    return generic_validate(
        url, lambda response: result(response, "modrinth", user),
        show_url=show_url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
