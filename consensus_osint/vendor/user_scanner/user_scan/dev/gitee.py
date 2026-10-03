from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_gitee(user):
    encoded = quote(user, safe="")
    return generic_validate(
        "https://gitee.com/api/v5/users/" + encoded, lambda response: result(response, "gitee", user),
        show_url="https://gitee.com/" + encoded,
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}, follow_redirects=False,
    )
