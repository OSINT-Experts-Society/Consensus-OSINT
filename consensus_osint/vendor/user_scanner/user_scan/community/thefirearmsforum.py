from consensus_osint.core.forum_redirects import member_result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request
from consensus_osint.vendor.user_scanner.core.result import Result

BASE_URL = "https://www.thefirearmsforum.com"


def validate_thefirearmsforum(user: str) -> Result:
    url = f"{BASE_URL}/members/"
    params = {"username": user}
    try:
        response = impersonate_request(url, params=params)
        return member_result(response, BASE_URL)
    except Exception as exc:
        return Result.error(exc, url=url)
