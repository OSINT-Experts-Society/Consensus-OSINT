"""Limited response parsing for retained, restricted member-search adapters."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

_MEMBER = re.compile(r"/members/([^/]+)\.(\d+)/?$")


def member_result(response, base_url):
    from consensus_osint.vendor.user_scanner.core.result import Result

    search_url = base_url + "/members/"
    if response.status_code == 202 or response.headers.get("cf-mitigated", "").lower() == "challenge":
        return Result.error("A challenge prevented the member lookup; no challenge replay was attempted", url=search_url)
    if response.status_code in (301, 302, 303):
        location = response.headers.get("location", "")
        try:
            if any(ord(char) < 32 or ord(char) == 127 for char in location) or "\\" in location:
                raise ValueError("invalid redirect characters")
            target = urlsplit(urljoin(search_url, location))
            origin = urlsplit(base_url)
            match = _MEMBER.fullmatch(target.path)
            if (not match or target.scheme != origin.scheme or target.hostname != origin.hostname
                    or (target.port if target.port is not None else 443) != (origin.port if origin.port is not None else 443)
                    or target.username or target.password):
                raise ValueError("not a same-origin member profile")
        except ValueError:
            return Result.error("Redirect did not identify a profile on this forum", url=search_url)
        # A URL slug is not a separately verified username. Retain its source.
        return Result.taken(extra={"profile_slug": match.group(1), "user_id": match.group(2),
                                   "_profile_field_source": "Fields parsed from the member-search redirect path"},
                            url=target._replace(query="", fragment="").geturl())
    if response.status_code == 200 and "The specified member cannot be found" in response.text:
        return Result.available(url=search_url)
    return Result.error(f"Unexpected member-search response (HTTP {response.status_code})", url=search_url)
