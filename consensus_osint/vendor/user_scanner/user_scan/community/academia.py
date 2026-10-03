from urllib.parse import quote

from consensus_osint.core.academia_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_academia(user: str) -> Result:
    url = f"https://independent.academia.edu/{quote(user, safe='')}"
    if "." in user:
        return Result.error("Handles containing a period are not addressable", url=url)
    return impersonate_validate(url, lambda response: result(response, user), show_url=url, allow_redirects=False)
