from urllib.parse import quote

from consensus_osint.core.spankbang_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate

# Retain the existing fingerprint; this does not establish current access.
IMPERSONATE = "safari17_0"


def validate_spankbang(user):
    url = "https://spankbang.com/profile/" + quote(user, safe="")
    return impersonate_validate(url, lambda response: result(response, user), impersonate=IMPERSONATE,
                                show_url=url, allow_redirects=False)
