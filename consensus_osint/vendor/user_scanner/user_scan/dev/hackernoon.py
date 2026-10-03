from urllib.parse import quote

from consensus_osint.core.developer_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_hackernoon(user):
    encoded = quote(user, safe="")
    return generic_validate(
        "https://us-central1-hackernoon-app.cloudfunctions.net/profilesApi/",
        lambda response: result(response, "hackernoon", user),
        show_url="https://hackernoon.com/u/" + encoded,
        params={"handle": user},
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
