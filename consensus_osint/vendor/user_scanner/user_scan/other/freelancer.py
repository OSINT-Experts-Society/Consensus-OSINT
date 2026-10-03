from urllib.parse import quote

from consensus_osint.core.freelancer_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_freelancer(user):
    return generic_validate(
        "https://www.freelancer.com/api/users/0.1/users", lambda response: result(response, user),
        show_url=f"https://www.freelancer.com/u/{quote(user, safe='')}",
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        params={"usernames[]": user, "compact": "true"}, follow_redirects=False,
    )
