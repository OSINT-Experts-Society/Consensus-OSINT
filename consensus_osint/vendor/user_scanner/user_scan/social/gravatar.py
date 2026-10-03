from urllib.parse import quote

from consensus_osint.core.gravatar_username_contracts import result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_gravatar(user):
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://en.gravatar.com/{encoded}.json", lambda response: result(response, user),
        show_url=f"https://gravatar.com/{encoded}",
        headers={"User-Agent": get_random_user_agent(), "Accept": "application/json"}, follow_redirects=False,
    )
