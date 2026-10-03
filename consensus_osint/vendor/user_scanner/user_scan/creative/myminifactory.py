from urllib.parse import quote

from consensus_osint.core.myminifactory_contracts import result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_myminifactory(user: str) -> Result:
    url = f"https://www.myminifactory.com/users/{quote(user, safe='')}"
    headers = {"User-Agent": get_random_user_agent(), "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    return generic_validate(url, lambda response: result(response, user), headers=headers, show_url=url, follow_redirects=False)
