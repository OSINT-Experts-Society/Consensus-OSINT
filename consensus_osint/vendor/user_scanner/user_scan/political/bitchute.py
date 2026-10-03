from urllib.parse import quote

from consensus_osint.core.bitchute_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_bitchute(user):
    return generic_validate(
        "https://api.bitchute.com/api/beta/channel", lambda response: result(response, user),
        method="POST", json={"channel_id": user}, headers={"Content-Type": "application/json"},
        show_url="https://www.bitchute.com/channel/" + quote(user, safe="") + "/", follow_redirects=False,
    )
