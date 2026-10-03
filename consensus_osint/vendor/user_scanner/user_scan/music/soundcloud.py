"""Retained public profile lookup with typed, permalink-bound hydration fields."""
from urllib.parse import quote

from consensus_osint.core.models import Status
from consensus_osint.core.soundcloud_contracts import response_outcome
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_soundcloud(user):
    url = "https://soundcloud.com/" + quote(user, safe="")
    show_url = url

    def process(response):
        status, fields, reason = response_outcome(response, user)
        if status is Status.FOUND:
            media = fields.pop("media", {})
            return Result.taken(extra=fields, media=media, url=show_url)
        if status is Status.NOT_FOUND:
            return Result.available(url=show_url)
        return Result.error(reason, url=show_url)

    return generic_validate(url, process, show_url=show_url, follow_redirects=True)
