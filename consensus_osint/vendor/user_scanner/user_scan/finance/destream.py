from urllib.parse import quote

from consensus_osint.core.finance_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_destream(user):
    encoded = quote(user, safe="")
    return generic_validate("https://api.destream.net/siteapi/v2/live/details/" + encoded, lambda response: result(response, "destream", user),
                            show_url="https://destream.net/live/" + encoded, headers={"Accept": "application/json"}, follow_redirects=False)
