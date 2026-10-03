from urllib.parse import quote

from consensus_osint.core.cups7_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_7cups(user: str) -> Result:
    encoded = quote(user, safe="")
    return impersonate_validate(
        f"https://www.7cups.com/apiv2/user/{encoded}", lambda response: result(response, user),
        show_url=f"https://www.7cups.com/@{encoded}", allow_redirects=False,
    )
