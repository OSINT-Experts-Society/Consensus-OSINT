from urllib.parse import quote

from consensus_osint.core.lnkbio_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_lnkbio(user: str) -> Result:
    url = f"https://lnk.bio/{quote(user, safe='')}"
    return generic_validate(url, lambda response: result(response, user), show_url=url, follow_redirects=False)
