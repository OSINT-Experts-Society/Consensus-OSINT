import json
import re
from urllib.parse import quote

from consensus_osint.core.coding_user_contracts import result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, make_request


def validate_leetcode(user: str) -> Result:
    if not (3 <= len(user) <= 30):
        return Result.error("Length must be between 3 and 30 characters")

    if not re.match(r"^[a-zA-Z0-9._-]+$", user):
        return Result.error("Can only use letters, numbers, underscores, periods, or hyphens")

    show_url = f"https://leetcode.com/u/{user}/"

    query = """query userPublicProfile($username: String!) { matchedUser(username: $username) { username profile { realName aboutMe userAvatar countryName company school ranking } } }"""
    variables = json.dumps({"username": user})
    url = f"https://leetcode.com/graphql?query={quote(query)}&variables={quote(variables)}"

    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": "application/json, text/plain, */*",
    }

    try:
        response = make_request(url, headers=headers, follow_redirects=False)
        return result(response, "leetcode", user).update(url=show_url)
    except Exception as e:
        return Result.error(e, url=show_url)
