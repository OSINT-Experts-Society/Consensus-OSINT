"""Reviewed Habbo public-profile API; identity binding is shared locally."""
from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_habbo_com(user):
    encoded_user = quote(user, safe="")
    show_url = f"https://www.habbo.com/profile/{encoded_user}"
    return generic_validate(
        "https://www.habbo.com/api/public/users",
        lambda response: result(response, "habbo", user),
        params={"name": user}, headers={"Accept": "application/json"},
        show_url=show_url, follow_redirects=False,
    )
