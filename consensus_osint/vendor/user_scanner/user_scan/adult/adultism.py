from urllib.parse import quote

from consensus_osint.core.adultism_contracts import friends, result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request, impersonate_validate

BASE_URL = "https://www.adultism.com"


def validate_adultism(user):
    url = BASE_URL + "/profile/" + quote(user, safe="")

    def process(response):
        found = result(response, user)
        if found.is_found():
            try:
                response = impersonate_request(url + "/friends", allow_redirects=False)
                found.extra.update(friends(response, user))
            except Exception:
                pass
        return found

    return impersonate_validate(url, process, show_url=url, allow_redirects=False)
