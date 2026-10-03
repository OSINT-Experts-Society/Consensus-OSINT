from urllib.parse import quote

from consensus_osint.core.donation_page_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_kofi(user):
    if "." in user:
        return Result.skipped(url="https://ko-fi.com")
    url = "https://ko-fi.com/" + quote(user, safe="")
    return generic_validate(url, lambda response: result(response, "kofi", user),
                              show_url=url, follow_redirects=False)
