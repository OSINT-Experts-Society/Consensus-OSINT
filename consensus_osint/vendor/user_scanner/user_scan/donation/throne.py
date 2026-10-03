import re

from consensus_osint.core.throne_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request, impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_throne(user):
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,50}", user):
        return Result.error("Username must be 3-50 letters, numbers, hyphens, or underscores.")
    url = f"https://throne.com/{user}"
    return impersonate_validate(url, lambda response: result(response, user, impersonate_request),
                                show_url=url, allow_redirects=False)
