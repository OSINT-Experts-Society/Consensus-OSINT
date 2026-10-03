import re

from consensus_osint.core.sourceforge_contracts import fields, page_fields, profile
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request
from consensus_osint.vendor.user_scanner.core.result import Result

# Retain the existing fingerprint; current provider availability is not assumed.
IMPERSONATE = "safari184"


def validate_sourceforge(user):
    if not re.fullmatch(r"[a-z0-9-]{3,30}", user):
        return Result.error("Use 3-30 lowercase letters, numbers, or dashes.")
    show_url = f"https://sourceforge.net/u/{user}/profile/"
    try:
        response = impersonate_request(f"https://sourceforge.net/rest/u/{user}/profile",
                                       impersonate=IMPERSONATE, allow_redirects=False)
    except Exception as exc:
        return Result.error(exc, url=show_url)
    data, reason = profile(response, user)
    if data is None:
        return Result.error(reason, url=show_url)
    extra, media = fields(data), {}
    try:
        response = impersonate_request(show_url, impersonate=IMPERSONATE, allow_redirects=False)
        more, media = page_fields(response, show_url)
        extra.update(more)
    except Exception:
        pass  # Optional page details cannot erase the bound API result.
    return Result.taken(extra=extra, media=media, url=show_url)
