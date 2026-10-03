from urllib.parse import quote

from consensus_osint.core.yaga_profiles import shop_result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_yaga_co_za(user: str) -> Result:
    query = user.lower()
    user = quote(query, safe="")
    url = f"https://www.yaga.co.za/{user}"
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def process(response):
        return shop_result(response, query)

    return generic_validate(url, process, headers=headers, show_url=url, follow_redirects=True)
