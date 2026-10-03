from urllib.parse import quote

from consensus_osint.core.riot_id_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_riot_id(user: str) -> Result:
    """Check if a Riot ID (Name#Tag) is registered across Riot Games titles."""
    show_url = "https://www.riotid-lookup.com"

    user = user.strip()
    if user.count("#") != 1:
        return Result.error("Riot ID format required: Name#Tag (e.g. TenZ#00005)")

    name, tag = user.split("#")
    if not name or not tag:
        return Result.error("Both name and tag are required (e.g. TenZ#00005)")

    if not (3 <= len(tag) <= 5):
        return Result.error("Tag must be 3-5 characters")

    url = f"https://www.riotid-lookup.com/api/lookup?riotId={quote(user, safe='')}"

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
    }

    return generic_validate(url, lambda response: result(response, user), show_url=show_url, headers=headers, follow_redirects=False)
