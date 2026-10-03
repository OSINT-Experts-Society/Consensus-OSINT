import urllib.parse
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result
from consensus_osint.core.profile_api_contracts import native_result

def validate_artstation(user: str) -> Result:
    encoded_user = urllib.parse.quote(user, safe="")
    url = f"https://www.artstation.com/users/{encoded_user}.json"
    show_url = f"https://www.artstation.com/{encoded_user}"

    def process(response) -> Result:
        return native_result("artstation", response, user)

    return impersonate_validate(
        url,
        process,
        warmup_url="https://www.artstation.com/",
        impersonate="chrome120",
        show_url=show_url,
    )
