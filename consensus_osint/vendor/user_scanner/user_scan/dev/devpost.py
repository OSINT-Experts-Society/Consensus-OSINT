from urllib.parse import quote

from consensus_osint.core.developer_page_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_devpost(user):
    url = "https://devpost.com/" + quote(user, safe="")
    return generic_validate(url, lambda response: result(response, "devpost", user),
                            show_url=url, follow_redirects=False)
