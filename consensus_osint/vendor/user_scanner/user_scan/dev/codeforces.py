from urllib.parse import quote

from consensus_osint.core.coding_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_codeforces(user):
    if not user or ";" in user or any(ord(c) < 32 for c in user):
        return Result.error("A single Codeforces handle is required")
    return generic_validate(
        "https://codeforces.com/api/user.info",
        lambda response: result(response, "codeforces", user),
        show_url="https://codeforces.com/profile/" + quote(user, safe=""),
        params={"handles": user},
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        follow_redirects=False,
    )
