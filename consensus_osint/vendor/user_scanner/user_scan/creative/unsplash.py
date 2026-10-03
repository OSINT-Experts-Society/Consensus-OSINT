from urllib.parse import quote

from consensus_osint.core.unsplash_contracts import downloads, result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request, impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_unsplash(user: str) -> Result:
    encoded = quote(user, safe="")
    url = f"https://unsplash.com/napi/users/{encoded}"

    def process(response):
        found = result(response, user)
        if found.is_found():
            try:
                total = downloads(impersonate_request(url + "/statistics", allow_redirects=False), user)
            except Exception:
                total = None
            if total is not None:
                found.extra["downloads"] = total
        return found

    return impersonate_validate(url, process, show_url=f"https://unsplash.com/@{encoded}", allow_redirects=False)
