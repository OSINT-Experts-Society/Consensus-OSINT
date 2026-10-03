from urllib.parse import quote

from consensus_osint.core.nexusmods_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_nexusmods(user: str) -> Result:
    url = f"https://www.nexusmods.com/profile/{quote(user, safe='')}"
    return impersonate_validate(url, lambda response: result(response, user), show_url=url, allow_redirects=False)
