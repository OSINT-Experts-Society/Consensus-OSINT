from urllib.parse import quote

from consensus_osint.core.polarsteps_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_polarsteps(user: str) -> Result:
    encoded = quote(user, safe="")
    return generic_validate(
        f"https://api.polarsteps.com/users/byusername/{encoded}", lambda response: result(response, user),
        headers={"Accept": "application/json", "Polarsteps-API-Version": "61"},
        show_url=f"https://www.polarsteps.com/{encoded}", follow_redirects=False,
    )
