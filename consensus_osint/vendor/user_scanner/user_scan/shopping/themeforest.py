from urllib.parse import quote

from consensus_osint.core.themeforest_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result

# Retain the existing transport fingerprint; current live compatibility is unverified.
IMPERSONATE = "safari184"


def validate_themeforest(user: str) -> Result:
    url = f"https://themeforest.net/user/{quote(user, safe='')}"
    return impersonate_validate(
        url, lambda response: result(response, user), impersonate=IMPERSONATE,
        show_url=url, allow_redirects=False,
    )
