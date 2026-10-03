import re
from urllib.parse import urlencode

from consensus_osint.core.vinted_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_vinted(user: str):
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", user):
        return Result.error("Invalid Vinted username")
    url = "https://www.vinted.pt/member/general/search"
    params = {"search_text": user}
    return generic_validate(
        url, lambda response: result(response, user), params=params,
        show_url=url + "?" + urlencode(params), follow_redirects=False,
    )
