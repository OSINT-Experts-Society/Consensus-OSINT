from urllib.parse import quote

from consensus_osint.core.pastebin_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_pastebin(user):
    url = f"https://pastebin.com/u/{quote(user, safe='')}"
    return generic_validate(url, lambda response: result(response, user), show_url=url, follow_redirects=False)
