from urllib.parse import quote

from consensus_osint.core.fragment_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_fragment(user):
    url = "https://fragment.com/username/" + quote(user, safe="")
    return generic_validate(url, lambda response: result(response, user), show_url=url, follow_redirects=False)
