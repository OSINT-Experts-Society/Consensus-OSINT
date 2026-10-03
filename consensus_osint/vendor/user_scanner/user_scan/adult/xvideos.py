from urllib.parse import quote

from consensus_osint.core.xvideos_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_xvideos(user):
    url = "https://www.xvideos.com/profiles/" + quote(user, safe="")
    return generic_validate(url, lambda response: result(response, user), show_url=url, follow_redirects=False)
