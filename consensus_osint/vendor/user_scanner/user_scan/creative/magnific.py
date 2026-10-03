from urllib.parse import quote

from consensus_osint.core.magnific_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_magnific(user: str) -> Result:
    url = f"https://www.magnific.com/author/{quote(user, safe='')}"
    return impersonate_validate(url, lambda response: result(response, user), show_url=url, allow_redirects=False)
