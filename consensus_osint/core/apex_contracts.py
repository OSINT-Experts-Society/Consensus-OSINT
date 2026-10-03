"""Bound Tracker.gg Apex profiles and independently typed optional fields."""

import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def profile(response, user, platform):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return None, reason
    try:
        root = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        root = None
    if not isinstance(root, dict) or has_service_error(root):
        return None, "No coherent profile response"
    data = root.get("data")
    if not isinstance(data, dict) or has_service_error(data):
        return None, "No coherent profile payload"
    info = data.get("platformInfo")
    if (not isinstance(info, dict) or has_service_error(info)
            or info.get("platformSlug") != platform
            or not isinstance(info.get("platformUserHandle"), str)
            or info["platformUserHandle"].casefold() != user.casefold()):
        return None, "Profile does not identify the requested platform and handle"
    return data, ""


def extract(hits, platforms):
    extra, media = {"platforms": ", ".join(platforms[p] for p in hits)}, {}
    for platform, data in hits.items():
        prefix = f"{platform}_" if len(hits) > 1 else ""
        info = data["platformInfo"]
        extra[f"{prefix}username"] = info["platformUserHandle"]
        if value := _url(info.get("avatarUrl")):
            media[f"{prefix}avatar"] = value
        user_info = data.get("userInfo")
        if isinstance(user_info, dict):
            if value := _text(user_info.get("countryCode")):
                extra[f"{prefix}country"] = value
            for source, target in (("isPremium", "premium"), ("isInfluencer", "influencer")):
                if type(user_info.get(source)) is bool:
                    extra[f"{prefix}{target}"] = user_info[source]
        metadata = data.get("metadata")
        if isinstance(metadata, dict) and (value := _text(metadata.get("activeLegendName"))):
            extra[f"{prefix}active_legend"] = value
        segments = data.get("segments")
        stats = segments[0].get("stats") if isinstance(segments, list) and segments and isinstance(segments[0], dict) else None
        if isinstance(stats, dict):
            for key in ("level", "kills"):
                stat = stats.get(key)
                if isinstance(stat, dict) and (value := _text(stat.get("displayValue"))):
                    extra[f"{prefix}{key}"] = value
    return extra, media
