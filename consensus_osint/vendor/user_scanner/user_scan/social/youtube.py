from urllib.parse import quote

from consensus_osint.core.youtube_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_youtube(user):
    handle = quote(user, safe="")
    return generic_validate(
        "https://www.youtube.com/@" + handle + "?cbrd=1&ucbcb=1",
        lambda response: result(response, user), show_url="https://youtube.com/@" + handle,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                 "Accept-Language": "en-US,en;q=0.9"}, follow_redirects=False,
    )
