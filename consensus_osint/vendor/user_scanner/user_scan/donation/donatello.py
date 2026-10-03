from urllib.parse import quote

from consensus_osint.core.donation_page_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate


def validate_donatello(user):
    url = "https://donatello.to/" + quote(user, safe="")
    return impersonate_validate(url, lambda response: result(response, "donatello", user),
                              show_url=url, allow_redirects=False)
