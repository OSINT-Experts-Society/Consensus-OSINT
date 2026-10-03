from consensus_osint.core.tumblr_contracts import result, valid_user
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_tumblr(user):
    if not valid_user(user):
        return Result.error("Only letters, numbers and hyphens allowed (max 32)")
    user = user.lower()
    url = "https://www.tumblr.com/" + user
    return impersonate_validate(url, lambda response: result(response, user), show_url=url, allow_redirects=False)
