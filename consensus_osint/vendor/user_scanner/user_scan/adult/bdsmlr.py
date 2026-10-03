from urllib.parse import quote

from consensus_osint.core.bdsmlr_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_bdsmlr(user):
    return generic_validate(
        "https://api-prod.bdsmlr.com/v2/api/get-blog", lambda response: result(response, user),
        show_url="https://bdsmlr.com/blog/" + quote(user, safe=""), method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={"blog_name": user}, follow_redirects=False,
    )
