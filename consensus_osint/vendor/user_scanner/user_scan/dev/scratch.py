from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_scratch(user):
    url = "https://api.scratch.mit.edu/users/" + quote(user, safe="")
    show_url = "https://scratch.mit.edu/users/" + quote(user, safe="")
    return generic_validate(
        url, lambda response: result(response, "scratch", user),
        show_url=show_url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
