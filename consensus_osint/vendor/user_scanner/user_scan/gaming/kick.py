from urllib.parse import quote

from consensus_osint.core.kick_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_kick(user: str) -> Result:
    encoded = quote(user, safe="")
    return impersonate_validate(
        f"https://kick.com/api/v2/channels/{encoded}",
        lambda response: result(response, user),
        show_url=f"https://kick.com/{encoded}",
        allow_redirects=False,
    )
