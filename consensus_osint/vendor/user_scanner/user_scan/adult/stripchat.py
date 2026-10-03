from urllib.parse import quote, urljoin, urlsplit

from consensus_osint.core.stripchat_contracts import body, extract, identity, model_page
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request, impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result

BASE_URL = "https://stripchat.com"
API_URL = BASE_URL + "/api/front"


def _viewer_redirect(raw, user):
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return False
    try:
        parsed = urlsplit(urljoin(BASE_URL, raw))
        return (parsed.scheme == "https" and parsed.netloc == "stripchat.com" and not parsed.query and not parsed.fragment
                and parsed.path.rstrip("/").casefold() == ("/user/" + quote(user, safe="")).casefold())
    except ValueError:
        return False


def validate_stripchat(user):
    url = BASE_URL + "/" + quote(user, safe="")

    def process(response):
        if response.status_code in (301, 302) and _viewer_redirect(response.headers.get("location"), user):
            return _viewer(user)
        return model_page(response, user)

    return impersonate_validate(url, process, show_url=url, allow_redirects=False)


def _viewer(user):
    try:
        lookup = body(impersonate_request(API_URL + "/users/user-ids/" + quote(user, safe=""), allow_redirects=False))
        user_id = lookup.get("id")
        if type(user_id) is not int or user_id <= 0:
            return Result.error("No valid Stripchat viewer ID")
        if "username" in lookup and (not isinstance(lookup["username"], str) or lookup["username"].casefold() != user.casefold()):
            return Result.error("Stripchat lookup identifies another viewer")
        account = body(impersonate_request(f"{API_URL}/v2/users/{user_id}", allow_redirects=False)).get("item")
        if not identity(account, user, user_id):
            return Result.error("No matching Stripchat viewer account")
        extra = {"type": "viewer", **extract(account)}
        try:
            profile = body(impersonate_request(f"{API_URL}/v2/users/{user_id}/profile", allow_redirects=False)).get("item")
            if identity(profile, user, user_id):
                extra.update(extract(profile))
        except Exception:
            pass
        return Result.taken(extra=extra, url=BASE_URL + "/user/" + quote(user, safe=""))
    except Exception as exc:
        return Result.error(exc)
