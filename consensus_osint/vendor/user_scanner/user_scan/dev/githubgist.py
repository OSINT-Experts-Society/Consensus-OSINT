from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_githubgist(user):
    encoded = quote(user, safe="")
    return generic_validate(
        "https://api.github.com/users/" + encoded, lambda response: result(response, "githubgist", user),
        show_url="https://gist.github.com/" + encoded,
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}, follow_redirects=False,
    )
