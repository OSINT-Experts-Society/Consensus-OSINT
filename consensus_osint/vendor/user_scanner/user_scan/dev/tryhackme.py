from urllib.parse import quote

from consensus_osint.core.profile_api_contracts import native_result

from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_tryhackme(user: str) -> Result:
    """Read the retained public-profile API; catalogue existence checks use a different route."""
    url = "https://tryhackme.com/api/v2/public-profile"
    show_url = "https://tryhackme.com/p/" + quote(user, safe="")

    def process(response):
        return native_result("tryhackme-profile", response, user)

    return impersonate_validate(
        url,
        process,
        warmup_url="https://tryhackme.com/",
        impersonate="chrome",
        show_url=show_url,
        allow_redirects=True,
        params={"username": user},
    )
