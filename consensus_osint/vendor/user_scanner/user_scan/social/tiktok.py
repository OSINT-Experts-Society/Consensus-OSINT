from urllib.parse import quote

from consensus_osint.core.tiktok_contracts import embed, valid_user
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_tiktok(user):
    if not valid_user(user):
        return Result.error("TikTok handles use letters, numbers, underscores and periods")
    handle = quote(user, safe="")
    return generic_validate(
        "https://www.tiktok.com/embed/@" + handle, lambda response: embed(response, user),
        show_url="https://www.tiktok.com/@" + handle, follow_redirects=False,
        headers={"User-Agent": get_random_user_agent(),
                 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                 "Accept-Language": "en-US,en;q=0.9"},
    )
