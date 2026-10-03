from urllib.parse import quote

from consensus_osint.core.profile_page_contracts import native_guard

import re

from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_bitbucket(user: str) -> Result:
    if not (1 <= len(user) <= 30):
        return Result.error("Length must be 1-30 characters.")

    if not re.fullmatch(r"^[a-z0-9][a-z0-9_-]*$", user):
        if re.search(r"[A-Z]", user):
            return Result.error("Use lowercase letters only.")

        return Result.error(
            "Only use lowercase letters, numbers, hyphens, and underscores."
        )

    encoded_user = quote(user, safe="")
    url = f"https://bitbucket.org/{encoded_user}/"
    show_url = f"https://bitbucket.org/{encoded_user}/"

    def process(response):
        guarded = native_guard("bitbucket", response, user)
        return guarded if guarded is not None else Result.taken(extra={"scope": "Bitbucket profile or workspace page"})

    return generic_validate(url, process, show_url=show_url, follow_redirects=True)
