from urllib.parse import quote

from consensus_osint.core.livejournal_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate


def validate_livejournal(user):
    return impersonate_validate(
        "https://www.livejournal.com/profile/", lambda response: result(response, user),
        params={"user": user}, show_url="https://www.livejournal.com/profile/?user=" + quote(user, safe=""),
        allow_redirects=False,
    )
