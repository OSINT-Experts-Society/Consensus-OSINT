from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_codewars(user):
    encoded = quote(user, safe="")
    url = "https://www.codewars.com/api/v1/users/" + encoded
    show_url = "https://www.codewars.com/users/" + encoded
    return generic_validate(
        url, lambda response: result(response, "codewars", user),
        show_url=show_url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
