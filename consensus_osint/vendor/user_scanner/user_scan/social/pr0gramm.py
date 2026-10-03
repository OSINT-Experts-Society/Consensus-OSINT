from urllib.parse import quote

from consensus_osint.core.pr0gramm_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_pr0gramm(user):
    return generic_validate(
        "https://pr0gramm.com/api/profile/info", lambda response: result(response, user),
        show_url="https://pr0gramm.com/user/" + quote(user, safe=""), params={"name": user},
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}, follow_redirects=False,
    )
