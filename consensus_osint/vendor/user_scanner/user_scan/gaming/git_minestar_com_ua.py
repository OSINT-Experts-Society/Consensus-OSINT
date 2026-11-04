from urllib.parse import quote

from consensus_osint.core.forge_profiles import native_result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_git_minestar_com_ua(user):
    encoded_user = quote(user, safe="")
    show_url = f"https://git.minestar.com.ua/{encoded_user}"
    url = f"https://git.minestar.com.ua/api/v1/users/{encoded_user}"
    return generic_validate(
        url,
        lambda response: native_result(response, user),
        show_url=show_url,
        headers={"Accept": "application/json"}, follow_redirects=False,
    )
