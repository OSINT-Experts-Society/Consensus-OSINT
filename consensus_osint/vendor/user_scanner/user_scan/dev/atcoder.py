from urllib.parse import quote

from consensus_osint.core.developer_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_atcoder(user):
    encoded = quote(user, safe="")
    return generic_validate(
        "https://atcoder.jp/api/users/exists/", lambda response: result(response, "atcoder", user),
        show_url=f"https://atcoder.jp/users/{encoded}", follow_redirects=False, params={"userScreenName": user},
    )
