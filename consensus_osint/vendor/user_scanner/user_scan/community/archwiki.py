from urllib.parse import quote

from consensus_osint.core.wiki_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_archwiki(user):
    if not user.strip() or "|" in user or any(ord(c) < 32 for c in user):
        return Result.error("A single MediaWiki username is required")
    return generic_validate(
        "https://wiki.archlinux.org/api.php",
        lambda response: result(response, user, "archwiki"),
        show_url="https://wiki.archlinux.org/title/User:" + quote(user, safe=""),
        params={
            "action": "query",
            "format": "json",
            "list": "users",
            "ususers": user,
            "usprop": "blockinfo|groups|editcount|registration|gender",
            "formatversion": 2,
        },
        follow_redirects=False,
    )
