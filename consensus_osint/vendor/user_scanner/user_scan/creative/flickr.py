import re
from urllib.parse import quote

from consensus_osint.core.flickr_contracts import public_profile, result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request, impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_flickr(user: str) -> Result:
    url = f"https://www.flickr.com/photos/{quote(user, safe='')}"

    def process(response):
        found = result(response, user)
        nsid = found.extra.get("user_id")
        if found.is_found() and isinstance(nsid, str) and re.fullmatch(r"[0-9]{1,25}@N[0-9]{2}", nsid):
            try:
                response = impersonate_request(f"https://www.flickr.com/people/{quote(nsid, safe='')}/", allow_redirects=False)
                found.extra.update(public_profile(response, nsid))
            except Exception:
                pass
        return found

    return impersonate_validate(url, process, show_url=url, allow_redirects=False)
