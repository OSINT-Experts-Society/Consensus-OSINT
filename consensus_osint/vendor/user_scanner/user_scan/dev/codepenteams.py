from urllib.parse import quote

from consensus_osint.core.codepen_contracts import process
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate, make_request


def validate_codepenteams(user):
    url = "https://codepen.io/team/" + quote(user, safe="")
    return generic_validate(url, lambda response: process(response, user, url, "Team", make_request),
                            show_url=url, follow_redirects=False)
