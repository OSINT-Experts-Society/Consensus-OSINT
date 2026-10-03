"""Throne profile data and constrained Next.js fallback requests."""

import json
import re
from datetime import datetime, timezone

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _object(text):
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) and not has_service_error(data) else None


def result(response, user, request):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["template", "style"]):
        node.decompose()
    scripts = page.select("script#__NEXT_DATA__")
    if len(scripts) != 1 or scripts[0].get("src"):
        return Result.error("No unique embedded creator data")
    data = _object(scripts[0].string or "")
    props = data.get("props") if data else None
    page_props = props.get("pageProps") if isinstance(props, dict) and not has_service_error(props) else None
    if not isinstance(page_props, dict) or has_service_error(page_props):
        return Result.error("Invalid creator page data")
    if "isFallback" in data and type(data["isFallback"]) is not bool:
        return Result.error("Invalid fallback flag")
    if data.get("isFallback") is True:
        build = data.get("buildId")
        if not isinstance(build, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", build):
            return Result.error("Invalid fallback build identifier")
        try:
            response = request(f"https://throne.com/_next/data/{build}/{user}.json",
                               headers={"x-nextjs-data": "1"}, allow_redirects=False)
        except Exception as exc:
            return Result.error(exc)
        issue, reason = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return Result.error(reason)
        payload = _object(response.text)
        page_props = payload.get("pageProps") if payload else None
    if (not isinstance(page_props, dict) or has_service_error(page_props)
            or "__N_REDIRECT" in page_props or "__N_REDIRECT_STATUS" in page_props):
        return Result.error("Fallback did not establish a creator profile")
    fallback = page_props.get("fallback")
    profile = fallback.get(f"$sub$public/useCreatorByUsername/{user}") if isinstance(fallback, dict) and not has_service_error(fallback) else None
    if not isinstance(profile, dict) or has_service_error(profile) or profile.get("username") != user:
        return Result.error("Creator identity does not match query")
    extra, media = {"username": user}, {}
    for source, target in (("_id", "id"), ("displayName", "fullname"), ("bio", "bio"),
                           ("creatorType", "creator_type"), ("mainContentPlatform", "main_platform")):
        if value := _text(profile.get(source)):
            extra[target] = value
    for source, target in (("isPartner", "partner"), ("isNSFW", "nsfw")):
        if type(profile.get(source)) is bool:
            extra[target] = profile[source]
    for source, target in (("createdAt", "joined"), ("updatedAt", "updated")):
        value = profile.get(source)
        if type(value) in (int, float) and 0 <= value <= 253402300799000:
            try:
                extra[target] = datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec="milliseconds")
            except (ValueError, OverflowError, OSError):
                pass
    interests = profile.get("interests")
    if isinstance(interests, list) and all(isinstance(value, str) for value in interests) and interests:
        extra["interests"] = interests
    links = profile.get("socialLinks")
    if isinstance(links, list):
        for link in links:
            if isinstance(link, dict) and (kind := _text(link.get("type"))) and kind.isidentifier() and (value := _url(link.get("url"))):
                extra["social_" + kind] = value
    for source, target in (("pictureUrl", "avatar"), ("backgroundPictureUrl", "banner")):
        if value := _url(profile.get(source)):
            media[target] = value
    return Result.taken(extra=extra, media=media)
