from urllib.parse import quote

from consensus_osint.core.substack_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_substack(user: str) -> Result:
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://substack.com/api/v1/user/{encoded}/public_profile",
        lambda response: result(response, user),
        show_url=f"https://substack.com/@{encoded}", follow_redirects=False,
    )
