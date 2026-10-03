from urllib.parse import quote

from consensus_osint.core.aparat_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_aparat(user: str) -> Result:
    encoded = quote(user, safe="")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
    }
    return generic_validate(
        f"https://www.aparat.com/api/fa/v1/user/user/information/username/{encoded}",
        lambda response: result(response, user), headers=headers,
        show_url=f"https://www.aparat.com/{encoded}", follow_redirects=False,
    )
