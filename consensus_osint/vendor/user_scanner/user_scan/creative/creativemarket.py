import json
import re
from html import unescape
from urllib.parse import quote

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.core.weekly_profile_contracts import profile_markup, script_matches
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


BASE_URL = "https://creativemarket.com/"
NOT_FOUND_MARKER = "Whoomp, there it isn&#039;t!"


def validate_creativemarket(user: str) -> Result:
    url = f"{BASE_URL}users/{quote(user, safe='')}"

    def process(response) -> Result:
        document = profile_markup(response, url)
        if response.status_code == 404:
            if NOT_FOUND_MARKER in document:
                return Result.available()
            return Result.error("Creative Market 404 response missing not-found marker")

        if response.status_code != 200:
            return Result.error(f"Unexpected status code: {response.status_code}")

        matches = script_matches(
            r"var _jsConfig = (?P<config>\{.*?\});\s*var APP", profile_markup(response, url, scripts=True)
        )
        if len(matches) != 1:
            return Result.error("Creative Market profile data not found")

        try:
            config = json.loads(matches[0]['config'], object_pairs_hook=_unique_object)
        except ValueError:
            return Result.error("Invalid Creative Market profile data")

        if not isinstance(config, dict) or has_service_error(config):
            return Result.error("Unexpected Creative Market configuration")
        profile = config.get("pageData")
        if not isinstance(profile, dict) or config.get("page_type") != "user_activity":
            return Result.error("Unexpected Creative Market profile payload")
        if has_service_error(profile):
            return Result.error("Conflicting Creative Market profile payload")

        username = profile.get("username")
        if not isinstance(username, str) or username.casefold() != user.casefold():
            return Result.error("Creative Market returned a different user")

        is_private = profile.get("isPrivate")
        extra = {
            "name": _profile_name(document, username),
            "bio": unescape(profile.get("userBio") or ""),
            "location": profile.get("userLocation"),
            "created": profile.get("userCreatedDate"),
            "followers": profile.get("numFollowers"),
            "following": profile.get("numFollowing"),
            "id": profile.get("userID"),
            "activity_public": not is_private if isinstance(is_private, bool) else None,
            "shop_owner": profile.get("shopExists"),
            "shop_title": profile.get("shopTitle"),
            "shop_rating": profile.get("shopReviewRating"),
            "shop_sales": profile.get("shopNumSales"),
        }
        for social in profile.get("socialLinks") or []:
            if isinstance(social, dict) and social.get("platform") and social.get("link"):
                extra[str(social["platform"]).lower()] = social["link"]

        return Result.taken(
            extra=extra,
            media={"avatar": profile.get("avatarUrl")},
        )

    return impersonate_validate(
        url,
        process,
        warmup_url=BASE_URL,
        allow_redirects=True,
    )


def _profile_name(document: str, username: str) -> str | None:
    match = re.search(
        rf"<title[^>]*>(.*?) \({re.escape(username)}\)\s*</title>",
        document,
        re.DOTALL | re.IGNORECASE,
    )
    return unescape(match.group(1)).strip() if match else None
