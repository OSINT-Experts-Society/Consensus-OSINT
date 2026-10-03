from urllib.parse import quote

from consensus_osint.core.finance_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_cropty(user):
    encoded = quote(user, safe="")
    return generic_validate("https://api.cropty.io/v1/auth/" + encoded, lambda response: result(response, "cropty", user),
                            show_url="https://www.cropty.io", headers={"Accept": "application/json"}, follow_redirects=False)
