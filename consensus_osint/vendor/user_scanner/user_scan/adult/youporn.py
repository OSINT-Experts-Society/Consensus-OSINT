from consensus_osint.core.youporn_contracts import BASE_URL, page_path, redirect_target, result
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_youporn(user: str) -> Result:
    pending = Result.error("No confirmed YouPorn public page")
    for namespace in ("pornstar", "amateur", "uservids"):
        url = BASE_URL + page_path(namespace, user)
        try:
            response = impersonate_request(url, allow_redirects=False)
            if response.status_code in (301, 302, 303, 307, 308):
                target = redirect_target(response.headers.get("location"), namespace, user)
                if target is not None:
                    response = impersonate_request(target, allow_redirects=False)
            parsed = result(response, user, namespace)
            if parsed.is_found():
                parsed.url = url
                return parsed
            pending = parsed
        except Exception as exc:
            pending = Result.error(exc)
    pending.url = BASE_URL + page_path("pornstar", user)
    return pending
