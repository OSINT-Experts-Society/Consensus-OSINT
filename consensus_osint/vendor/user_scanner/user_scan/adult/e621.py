from urllib.parse import quote

from consensus_osint.core.e621_contracts import HEADERS, result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate


def validate_e621(user):
    show_url = "https://e621.net/users/" + quote(user, safe="")
    return impersonate_validate(show_url + ".json", lambda response: result(response, user),
                                show_url=show_url, headers=HEADERS, allow_redirects=False)
