from urllib.parse import quote

from consensus_osint.core.solo_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_solo_to(user: str) -> Result:
    url = f"https://solo.to/{quote(user, safe='')}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    return generic_validate(url, lambda response: result(response, user), headers=headers, show_url=url, follow_redirects=False)
