from urllib.parse import quote

from consensus_osint.core.monkeytype_contracts import availability, result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_monkeytype(user: str) -> Result:
    safe_user = quote(user, safe="")
    show_url = f"https://monkeytype.com/profile/{safe_user}"
    headers = {"User-Agent": get_random_user_agent(), "Accept": "application/json, text/plain, */*", "Accept-Encoding": "identity", "Accept-Language": "en-US,en;q=0.9"}

    def process(response):
        action, reason = availability(response, user)
        if action == "available":
            return Result.available(extra={"scope": "Name available for registration"})
        if action == "profile":
            return generic_validate(
                f"https://api.monkeytype.com/users/{safe_user}/profile?isUid=false",
                lambda profile: result(profile, user), show_url=show_url,
                headers=headers, follow_redirects=False,
            )
        return Result.error(reason)

    return generic_validate(
        f"https://api.monkeytype.com/users/checkName/{safe_user}", process,
        show_url=show_url, headers=headers, follow_redirects=False,
    )
