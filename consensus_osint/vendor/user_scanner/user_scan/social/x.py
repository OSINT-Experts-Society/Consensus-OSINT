from consensus_osint.core.x_contracts import availability, profile, valid_user
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_x(user):
    if not valid_user(user):
        return Result.error("X handles require 1-15 letters, numbers or underscores")
    show_url = "https://x.com/" + user
    headers = {"User-Agent": get_random_user_agent(), "Accept": "application/json"}
    result = generic_validate("https://api.vxtwitter.com/" + user, lambda response: profile(response, user),
                              show_url=show_url, headers=headers, follow_redirects=False)
    if result.is_found():
        return result
    return generic_validate("https://api.twitter.com/i/users/username_available.json",
                            lambda response: availability(response, user), params={"username": user},
                            show_url=show_url, headers=headers, follow_redirects=False)
