import re
from urllib.parse import quote

from consensus_osint.core.npm_scope_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_npmjs(user):
    if re.search(r"[A-Z]", user):
        return Result.error("Username cannot contain uppercase letters.")
    url = "https://www.npmjs.com/~" + quote(user, safe="")
    return impersonate_validate(url, lambda response: result(response, user),
                                headers={"x-spiferack": "1"}, show_url=url, allow_redirects=False)
