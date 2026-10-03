from urllib.parse import quote

from consensus_osint.core.etoro_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_etoro(user):
    encoded = quote(user, safe="")
    return generic_validate("https://www.etoro.com/api/logininfo/v1.1/users/" + encoded,
                            lambda response: result(response, user),
                            show_url="https://www.etoro.com/people/" + encoded,
                            headers={"Accept": "application/json", "Referer": "https://www.etoro.com/"},
                            follow_redirects=False)
