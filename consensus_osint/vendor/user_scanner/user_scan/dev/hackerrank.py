from urllib.parse import quote

from consensus_osint.core.developer_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_hackerrank(user):
    encoded = quote(user, safe="")
    return generic_validate(
        "https://www.hackerrank.com/rest/contests/master/hackers/" + encoded + "/profile",
        lambda response: result(response, "hackerrank", user),
        show_url="https://www.hackerrank.com/" + encoded,
        params=None,
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
