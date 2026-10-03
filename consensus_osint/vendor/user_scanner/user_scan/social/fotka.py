from urllib.parse import quote

from consensus_osint.core.fotka_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_fotka(user):
    return generic_validate(
        "https://api.fotka.com/v2/user/dataStatic", lambda response: result(response, user),
        show_url="https://fotka.com/profil/" + quote(user, safe=""), params={"login": user},
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        follow_redirects=False,
    )
