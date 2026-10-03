from urllib.parse import quote

from consensus_osint.core.producthunt_contracts import result, valid_user
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_producthunt(user: str) -> Result:
    if not valid_user(user):
        return Result.error("Use 2-32 letters, numbers or underscores.")
    url = f"https://www.producthunt.com/@{quote(user, safe='')}"
    return impersonate_validate(url, lambda response: result(response, user), show_url=url, allow_redirects=False)
