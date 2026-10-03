from urllib.parse import quote

from consensus_osint.core.rules import native_public_page
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, make_request


def validate_harvard(user: str) -> Result:
    query = user
    user = quote(user, safe="")
    url = f"https://cyber.harvard.edu/people/{user}"
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        response = make_request(url, headers=headers, follow_redirects=True)
        return native_public_page(response, query).update(url=url)
    except Exception as exc:
        return Result.error(exc, url=url)
