from urllib.parse import quote

from consensus_osint.core.forge_profiles import native_result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_gitea(user):
    query = user
    user = quote(user, safe="")
    url = f"https://gitea.com/api/v1/users/{user}"
    show_url = f"https://gitea.com/{user}"

    def process(response):
        return native_result(response, query)

    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    return generic_validate(url, process, show_url=show_url, headers=headers)
