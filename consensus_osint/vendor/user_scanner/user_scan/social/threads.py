from consensus_osint.core.threads_contracts import result, valid_user
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_threads(user):
    if not valid_user(user):
        return Result.error("Invalid Threads username")
    url = f"https://www.threads.com/@{user}"
    return impersonate_validate(url, lambda response: result(response, user),
                                show_url=url, allow_redirects=False)
