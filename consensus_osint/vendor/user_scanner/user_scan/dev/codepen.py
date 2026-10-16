from urllib.parse import quote

from consensus_osint.core.codepen_contracts import process, profile_request
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate


def validate_codepen(user):
    url = "https://codepen.io/" + quote(user, safe="")
    return impersonate_validate(url, lambda response: process(response, user, url, "User", profile_request),
                                show_url=url, allow_redirects=False)
