import json
import re
from datetime import datetime, timezone
from urllib.parse import quote

from consensus_osint.core.weekly_profile_contracts import profile_markup, script_matches
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_artbreeder(user: str) -> Result:
    url = f"https://www.artbreeder.com/{quote(user, safe='')}"

    def process(response) -> Result:
        document = profile_markup(response, url, scripts=True)
        if response.status_code == 404 and script_matches(r'error: \{message:"User not found"\}', document):
            return Result.available()
        if response.status_code != 200:
            return Result.error(f"Unexpected response status: {response.status_code}")

        profiles = script_matches(
            r"profileUser:\{(?P<profile>.*?),socials:\{(?P<socials>.*?)\},isFollowed", document
        )
        if len(profiles) != 1:
            return Result.error("Profile payload missing from Artbreeder response")

        profile, socials = profiles[0]['profile'], profiles[0]['socials']
        if len(re.findall(r'(?:^|,)username:', profile)) != 1:
            return Result.error("Ambiguous Artbreeder identity")
        username = _value(profile, "username")
        if not isinstance(username, str) or username.casefold() != user.casefold():
            return Result.error("Profile payload does not match the requested handle")

        extra = {
            "id": _value(profile, "id"),
            "display_username": _value(profile, "usernameRaw"),
            "bio": _value(profile, "bio"),
            "followers": _value(profile, "numFollowers"),
            "following": _value(profile, "numFollowing"),
            "suspended": _value(profile, "suspended"),
        }
        if favorite_keys := re.search(r"(?:^|,)favoriteImageKeys:(\[[^\]]*\])", profile):
            try:
                extra["favorite_count"] = len(json.loads(favorite_keys.group(1)))
            except json.JSONDecodeError:
                pass

        if isinstance(created_at := _value(profile, "created_at"), int):
            extra["joined"] = datetime.fromtimestamp(created_at / 1000, timezone.utc).date().isoformat()

        role_id = _value(profile, "role")
        if isinstance(role_id, int) and (role := {1: "AB Team", 2: "Moderator"}.get(role_id)):
            extra["role"] = role

        if subscription_match := re.search(r"subscription:\{.*?product:\{(.*?)\}\}", profile):
            subscription = _value(subscription_match.group(1), "name")
            if isinstance(subscription, str) and subscription != "free":
                extra["subscription_badge"] = subscription.replace("_", " ").title()

        for field, label in (
            ("email", "public_email"),
            ("twitter", "twitter"),
            ("twitterUsername", "twitter_username"),
            ("tiktok", "tiktok"),
            ("instagram", "instagram"),
            ("website", "website"),
        ):
            extra[label] = _value(socials, field)

        media = (
            {"avatar": f"https://artbreeder.b-cdn.net/imgs/{image_key}.jpeg?width=256"}
            if isinstance(image_key := _value(profile, "profileImageKey"), str)
            else {}
        )
        return Result.taken(extra=extra, media=media)

    return generic_validate(url, process, show_url=url)


def _value(payload: str, field: str) -> str | int | bool | None:
    match = re.search(
        rf"(?:^|,){field}:(?:new Date\()?(-?\d+|true|false|null|void 0|\"(?:\\.|[^\"\\])*\")\)?",
        payload,
    )
    if not match or match.group(1) == "void 0":
        return None
    return json.loads(match.group(1))
