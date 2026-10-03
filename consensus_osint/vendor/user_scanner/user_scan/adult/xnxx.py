from urllib.parse import quote

from consensus_osint.core.xnxx_contracts import availability, public_profile
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request, impersonate_validate

BASE_URL = "https://www.xnxx.com"
HEADERS = {"X-Requested-With": "XMLHttpRequest", "Referer": BASE_URL + "/account/create"}


def validate_xnxx(user):
    show_url = BASE_URL + "/pornstar/" + quote(user, safe="")

    def process(response):
        result = availability(response, user)
        if result.is_found():
            try:
                profile = public_profile(impersonate_request(show_url, allow_redirects=False), user)
                if profile.is_found():
                    result.update(extra=profile.extra, media=profile.media)
                    result.extra["scope"] = "Matching XNXX public profile; not proof of ownership"
            except Exception:
                pass
        return result

    return impersonate_validate(BASE_URL + "/account/checkprofilename", process, show_url=show_url,
                                params={"profile": user}, headers=HEADERS, allow_redirects=False)
