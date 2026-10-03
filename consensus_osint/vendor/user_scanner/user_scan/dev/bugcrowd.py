from urllib.parse import quote

from consensus_osint.core.developer_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_bugcrowd(user):
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://bugcrowd.com/profile-service/v1/profiles/{encoded}", lambda response: result(response, "bugcrowd", user),
        show_url=f"https://bugcrowd.com/h/{encoded}", follow_redirects=False,
    )
