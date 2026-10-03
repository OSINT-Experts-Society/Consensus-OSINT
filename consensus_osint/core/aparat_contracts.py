"""Aparat matching user attributes and typed optional profile metadata."""

import json
import re

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _count(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    return None


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No successful Aparat response")
    record = data.get("data")
    if not isinstance(record, dict) or has_service_error(record):
        return Result.error("No coherent Aparat user data")
    attrs = record.get("attributes")
    if (not isinstance(attrs, dict) or has_service_error(attrs)
            or not isinstance(attrs.get("username"), str) or attrs["username"].casefold() != user.casefold()):
        return Result.error("No matching Aparat username")
    extra, media = {"username": attrs["username"]}, {}
    for source, target in (("name", "name"), ("descr", "bio")):
        if value := _text(attrs.get(source)):
            extra[target] = value
    for sources, target in ((("follower_cnt_num", "follower_cnt"), "followers"), (("follow_cnt",), "following"), (("video_cnt",), "videos")):
        for source in sources:
            value = _count(attrs.get(source))
            if value is not None:
                extra[target] = value
                break
        else:
            if value := _text(attrs.get(sources[-1])):
                extra[target + "_display"] = value
    if value := _url(attrs.get("url")):
        if value.rstrip("/") not in ("http://www.aparat.com", "https://www.aparat.com"):
            extra["website"] = value
    for key in ("pic_b", "pic_m", "pic_s"):
        if value := _url(attrs.get(key)):
            media["avatar"] = value
            break
    return Result.taken(extra=extra, media=media)
