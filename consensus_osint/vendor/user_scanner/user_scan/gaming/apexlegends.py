from urllib.parse import quote

from consensus_osint.core.apex_contracts import extract, profile
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request
from consensus_osint.vendor.user_scanner.core.result import Result

API_URL = "https://api.tracker.gg/api/v2/apex/standard/profile"
PROFILE_URL = "https://apex.tracker.gg/apex/profile"

# Apex accounts are per-platform: a handle can resolve on PSN and miss on the
# other two, so a single namespace never settles availability.
PLATFORMS = {"origin": "EA", "psn": "PlayStation", "xbl": "Xbox"}

HEADERS = {
    "Accept-Language": "en-US,en;q=0.5",
    "Origin": "https://apex.tracker.gg",
    "Referer": "https://apex.tracker.gg/",
}


def validate_apexlegends(user: str) -> Result:
    encoded = quote(user, safe="")
    show_url = f"{PROFILE_URL}/origin/{encoded}/overview"

    hits: dict[str, dict] = {}
    errors: list[str] = []

    for platform in PLATFORMS:
        try:
            response = impersonate_request(
                f"{API_URL}/{platform}/{encoded}", headers=HEADERS, allow_redirects=False
            )
        except Exception as e:
            errors.append(f"{platform}: {e}")
            continue

        data, reason = profile(response, user, platform)
        if data is None:
            errors.append(f"{platform}: {reason}")
            continue

        hits[platform] = data

    if hits:
        extra, media = extract(hits, PLATFORMS)
        if errors:
            extra["inconclusive_platforms"] = "; ".join(errors)
        first = next(iter(hits))
        return Result.taken(extra=extra, media=media, url=f"{PROFILE_URL}/{first}/{encoded}/overview")

    return Result.error("; ".join(errors) or "No matching Apex profile evidence", url=show_url)
