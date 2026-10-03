from urllib.parse import quote

from consensus_osint.core.developer_page_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_wordpress(user):
    url = "https://profiles.wordpress.org/" + quote(user, safe="") + "/"
    return generic_validate(url, lambda response: result(response, "wordpress", user),
                            show_url=url, follow_redirects=False)
