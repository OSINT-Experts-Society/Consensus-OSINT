from urllib.parse import quote

from consensus_osint.core.mixcloud_contracts import result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_mixcloud(user: str) -> Result:
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://api.mixcloud.com/{encoded}/", lambda response: result(response, user),
        show_url=f"https://www.mixcloud.com/{encoded}/",
        headers={"User-Agent": get_random_user_agent(), "Accept": "application/json"},
        follow_redirects=False,
    )
