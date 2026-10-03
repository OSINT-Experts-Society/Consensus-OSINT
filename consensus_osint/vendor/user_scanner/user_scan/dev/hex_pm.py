from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_hex_pm(user):
    url = "https://hex.pm/api/users/" + quote(user, safe="")
    show_url = "https://hex.pm/users/" + quote(user, safe="")
    return generic_validate(
        url, lambda response: result(response, "hex_pm", user),
        show_url=show_url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
