from urllib.parse import quote

from consensus_osint.core.medium_contracts import result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_medium(user: str) -> Result:
    encoded = quote(user, safe="")
    url = f"https://medium.com/@{encoded}"
    for kind, target in (("json", url + "?format=json"), ("html", url), ("feed", f"https://medium.com/feed/@{encoded}")):
        try:
            parsed = result(impersonate_request(target, allow_redirects=False), user, kind)
        except Exception:
            continue
        if parsed.is_found():
            return parsed.update(url=url)
    return Result.error("Medium views did not establish a matching public profile", url=url)
