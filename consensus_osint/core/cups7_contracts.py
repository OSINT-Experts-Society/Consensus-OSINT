"""7 Cups matching screen-name evidence and independent optional metadata."""

import html
import json
import math
import re
from datetime import datetime, timezone
from urllib.parse import urljoin

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _integer(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        return int(value)
    return None


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    if "x-amzn-waf-action" in response.headers:
        return Result.error("AWS WAF challenge triggered")
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if (not isinstance(data, dict) or has_service_error(data)
            or not isinstance(data.get("screenName"), str) or data["screenName"].casefold() != user.casefold()):
        return Result.error("No successful matching 7 Cups screen name")
    extra, media = {"screen_name": data["screenName"]}, {}
    role = _text(data.get("listType"))
    if role is None and isinstance(data.get("userType"), str):
        role = {"l": "listener", "m": "member", "t": "therapist"}.get(data["userType"])
    if role:
        extra["type"] = role
    for key in ("userID", "memID", "listID"):
        value = data.get(key)
        if _text(value) or (type(value) is int and value > 0):
            extra["user_id"] = value
            break
    for key in ("bio", "quote"):
        if value := _text(data.get(key)):
            extra[key] = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", value))).strip()
    for source, target in (("Country", "country"), ("language", "language"), ("points_formatted", "points_display"), ("lastActive", "last_active")):
        if value := _text(data.get(source)):
            extra[target] = value
    for source, target in (("age", "age"), ("numConversations", "conversations"), ("compassionHearts", "compassion_hearts"), ("forumUpvotes", "forum_upvotes"), ("R_numratings", "ratings")):
        if (value := _integer(data.get(source))) is not None:
            extra[target] = value
    for key in ("listenerLevel", "memberLevel"):
        value = data.get(key)
        if _text(value) or _integer(value) is not None:
            extra["level"] = value
            break
    for source, target in (("signupDateU", "joined"), ("approvalDateU", "listener_since")):
        stamp = _integer(data.get(source))
        if stamp is not None and stamp <= 253402300799:
            try:
                extra[target] = datetime.fromtimestamp(stamp, tz=timezone.utc).strftime("%Y-%m-%d")
            except (ValueError, OverflowError, OSError):
                pass
    rating = data.get("overallRating")
    if _text(rating) or (type(rating) is int and rating >= 0) or (type(rating) is float and math.isfinite(rating) and rating >= 0):
        extra["rating"] = rating
    online = data.get("onlineNow")
    if type(online) is bool or (type(online) is int and online in (0, 1)):
        extra["online"] = bool(online)
    badges = data.get("badges")
    if isinstance(badges, list):
        names = [name for item in badges if isinstance(item, dict) and not has_service_error(item)
                 and (item.get("active") is True or (type(item.get("active")) is int and item["active"] == 1))
                 and (name := _text(item.get("badgeName")))]
        if names:
            extra["badges"] = ", ".join(names)
    for key in ("imgURL", "image"):
        value = _text(data.get(key))
        if value and (url := _url(urljoin("https://www.7cups.com/", value))):
            media["avatar"] = url
            break
    return Result.taken(extra=extra, media=media)
