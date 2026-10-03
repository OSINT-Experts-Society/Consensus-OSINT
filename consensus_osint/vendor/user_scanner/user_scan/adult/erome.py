from urllib.parse import quote

from consensus_osint.core.erome_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate


def validate_erome(user):
    url = "https://www.erome.com/" + quote(user, safe="")
    return impersonate_validate(url, lambda response: result(response, user), show_url=url, allow_redirects=False)
