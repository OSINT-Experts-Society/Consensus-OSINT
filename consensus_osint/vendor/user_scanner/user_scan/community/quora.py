from urllib.parse import quote

from consensus_osint.core.quora_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_quora(user: str) -> Result:
    url = f"https://www.quora.com/profile/{quote(user, safe='')}"
    return generic_validate(url, lambda response: result(response, user), show_url=url, follow_redirects=False)
