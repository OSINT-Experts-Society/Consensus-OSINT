from urllib.parse import quote

from consensus_osint.core.microsoft_learn_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_microsoftlearn(user):
    encoded = quote(user, safe="")
    return generic_validate("https://learn.microsoft.com/api/profiles/" + encoded,
                            lambda response: result(response, user),
                            show_url="https://learn.microsoft.com/en-us/users/" + encoded + "/",
                            headers={"Accept": "application/json"}, follow_redirects=False)
