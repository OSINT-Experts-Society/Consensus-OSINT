import base64
from urllib.parse import quote, urlsplit

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.profile_page_contracts import native_guard
from consensus_osint.core.provider_contracts import has_service_error

from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request, impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result

WARMUP_URL = "https://www.tripadvisor.com/"
GRAPHQL_URL = "https://www.tripadvisor.com/data/graphql/ids"

# Retained persisted GraphQL query; its current schema/access is not verified.
# Supplementary fields require an explicit matching username. If that evidence
# is unavailable, retain the independently matched page without these details.
PROFILE_QUERY_ID = "b7f6eb32ff629f60"


def validate_tripadvisor(user):
    encoded_user = quote(user, safe="")
    url = f"https://www.tripadvisor.com/Profile/{encoded_user}"

    def process(response):
        guarded = native_guard("tripadvisor", response, user)
        if guarded is not None:
            return guarded
        extra, media = _fetch_profile(user)
        return Result.taken(extra=extra, media=media)

    return impersonate_validate(url, process, warmup_url=WARMUP_URL, show_url=url)


def _fetch_profile(user: str) -> tuple[dict, dict]:
    payload = [
        {
            "variables": {"username": user},
            "extensions": {"preRegisteredQueryId": PROFILE_QUERY_ID},
        }
    ]
    # Metadata is best-effort: a parsing failure must never turn a found
    # account into an error, so the whole enrichment is guarded.
    try:
        response = impersonate_request(
            GRAPHQL_URL, method="POST", warmup_url=WARMUP_URL, json=payload
        )
        issue, _ = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return {}, {}
        envelope = response.json()
        if (not isinstance(envelope, list) or len(envelope) != 1 or not isinstance(envelope[0], dict)
                or has_service_error(envelope[0])):
            return {}, {}
        data = envelope[0].get("data")
        if not isinstance(data, dict) or has_service_error(data):
            return {}, {}
        profiles = data.get("memberProfiles")
        if not isinstance(profiles, list) or len(profiles) != 1:
            return {}, {}
        profile = profiles[0]
        if (not isinstance(profile, dict) or has_service_error(profile)
                or not isinstance(profile.get("username"), str) or profile["username"].casefold() != user.casefold()):
            return {}, {}
        return _parse_profile(profile)
    except Exception:
        return ({}, {})


def _parse_profile(profile: dict) -> tuple[dict, dict]:
    extra, media = {}, {}
    for source, target in (("displayName", "name"), ("userId", "user_id"), ("bio", "bio"), ("created", "joined")):
        value = profile.get(source)
        if isinstance(value, str) and value.strip():
            extra[target] = value
    if type(profile.get("userId")) is int and profile["userId"] > 0:
        extra["user_id"] = profile["userId"]
    if type(profile.get("isVerified")) is bool:
        extra["verified"] = profile["isVerified"]
    for name, value in (("hometown", _extract_hometown(profile)), ("website", _decode_website(profile.get("website")))):
        if value:
            extra[name] = value
    avatar = profile.get("avatar")
    sizes = avatar.get("photoSizes") if isinstance(avatar, dict) else None
    if isinstance(sizes, list):
        valid = [item for item in sizes if isinstance(item, dict) and type(item.get("width")) is int
                 and item["width"] >= 0 and _web_url(item.get("url"))]
        if valid:
            media["avatar"] = max(valid, key=lambda item: item["width"])["url"]
    return extra, media


def _extract_hometown(profile: dict) -> str | None:
    # Nested optional fields can be absent, null or malformed independently.
    hometown = profile.get("hometown")
    if not isinstance(hometown, dict):
        return None
    location = hometown.get("location")
    names = location.get("additionalNames") if isinstance(location, dict) else None
    long_name = names.get("long") if isinstance(names, dict) else None
    if isinstance(long_name, str) and long_name.strip():
        return long_name
    # No resolved location: fall back to the free-text hometown, unless it is
    # just the numeric locationId echoed back as a string.
    fallback = hometown.get("fallbackString")
    if isinstance(fallback, str) and fallback.strip() and not fallback.isdigit():
        return fallback
    return None


def _decode_website(encoded: str | None) -> str | None:
    if not isinstance(encoded, str) or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except Exception:
        return None
    # TripAdvisor wraps the real URL as <rand>_<url>_<rand>; drop both wrappers.
    inner = decoded.split("_", 1)[-1].rsplit("_", 1)[0].strip()
    return inner if _web_url(inner) else None


def _web_url(value):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        return False
    try:
        parsed = urlsplit(value)
        return (parsed.scheme in ("http", "https") and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None)
    except ValueError:
        return False
