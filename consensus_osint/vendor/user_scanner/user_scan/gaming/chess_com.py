from urllib.parse import quote

from consensus_osint.core.named_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_chess_com(user):
    url = "https://api.chess.com/pub/player/" + quote(user.lower(), safe="")
    show_url = "https://www.chess.com/member/" + quote(user, safe="")
    return generic_validate(
        url, lambda response: result(response, "chess_com", user),
        show_url=show_url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
