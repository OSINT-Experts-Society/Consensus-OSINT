from urllib.parse import quote

from consensus_osint.core.bandlab_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_bandlab(user: str) -> Result:
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://www.bandlab.com/api/v1.3/users/{encoded}", lambda response: result(response, user),
        show_url=f"https://www.bandlab.com/{encoded}", follow_redirects=False,
    )
