from urllib.parse import quote

from consensus_osint.core.profile_page_contracts import native_guard

import re
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, make_request


def validate_itch_io(user: str) -> Result:
    if not (2 <= len(user) <= 25):
        return Result.error("Length must be 2-25 characters.")

    if not re.fullmatch(r"^[a-z0-9_-]+$", user):
        if re.search(r"[A-Z]", user):
            return Result.error("Use lowercase letters only.")
        return Result.error(
            "Only use lowercase letters, numbers, underscores, and hyphens."
        )

    encoded_user = quote(user, safe="")
    url = f"https://itch.io/profile/{encoded_user}"
    show_url = f"https://itch.io/profile/{encoded_user}"

    try:
        response = make_request(url, follow_redirects=True)
        guarded = native_guard("itch_io", response, user)
        if guarded is not None:
            return guarded.update(url=show_url)
        if response.status_code == 200:
            html = response.text
            extra = {}
            title = re.search(r'<title>([^<]+)- itch.io</title>', html)
            if title:
                extra["name"] = title.group(1).strip()
            return Result.taken(extra=extra, url=show_url)
        elif response.status_code == 404:
            return Result.available(url=show_url)
        else:
            return Result.error(f"Unexpected status: {response.status_code}", url=show_url)
    except Exception as e:
        return Result.error(e, url=show_url)
