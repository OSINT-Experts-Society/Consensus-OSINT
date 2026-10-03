from urllib.parse import quote

from consensus_osint.core.photo35_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_35photo(user: str) -> Result:
    url = f"https://35photo.pro/@{quote(user, safe='')}/"
    return generic_validate(url, lambda response: result(response, user), show_url=url, follow_redirects=False)
