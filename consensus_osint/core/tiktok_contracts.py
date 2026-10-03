"""TikTok creator oEmbed identity, without rendering supplied markup."""
import json
import re
from urllib.parse import unquote, urlsplit

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error
from .soundcloud_contracts import _Scripts


def _author(url, user):
    if not _url(url) or "\\" in url:
        return False
    try:
        parts = urlsplit(url)
        return (parts.scheme == "https" and parts.hostname == "www.tiktok.com"
                and parts.port in (None, 443) and not parts.query and not parts.fragment
                and unquote(parts.path).rstrip("/").casefold() == "/@" + user.casefold())
    except ValueError:
        return False


def oembed(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous TikTok oEmbed response")
    if (not isinstance(data, dict) or has_service_error(data) or data.get("type") != "rich"
            or data.get("version") != "1.0"
            or ("provider_name" in data and data["provider_name"] != "TikTok")
            or ("provider_url" in data and data["provider_url"] not in ("https://www.tiktok.com", "https://www.tiktok.com/"))
            or not _author(data.get("author_url"), user)):
        return Result.error("No matching TikTok creator embed")
    extra = {"author_url": data["author_url"], "scope": "TikTok creator embed; not proof of ownership"}
    for key, target in (("author_name", "name"), ("title", "title")):
        if value := _text(data.get(key)):
            extra[target] = value
    return Result.taken(extra=extra)


class _EmbedScripts(_Scripts):
    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        if tag == "script":
            values = dict(attrs)
            eligible = (not self.ignored and len(values) == len(attrs) and "src" not in values
                        and values.get("id") == "__FRONTITY_CONNECT_STATE__"
                        and (values.get("type") or "").lower() in ("", "application/json"))
            self.current = [] if eligible else None


def valid_user(user):
    return isinstance(user, str) and re.fullmatch(r"[A-Za-z0-9_.]+", user) is not None


def embed(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        scripts = _EmbedScripts(response.text).scripts
        if len(scripts) != 1:
            raise ValueError("Missing or ambiguous TikTok embed state")
        state = json.loads(scripts[0], object_pairs_hook=_unique_object)
        if not isinstance(state, dict) or has_service_error(state):
            raise ValueError("Failed embed state")
        source = state.get("source")
        if not isinstance(source, dict) or has_service_error(source):
            raise ValueError("Failed embed source")
        data = source.get("data")
        if not isinstance(data, dict) or has_service_error(data):
            raise ValueError("Failed embed data")
        matches = [value for key, value in data.items() if key.casefold() == ("/embed/@" + user).casefold()]
        if len(matches) != 1 or not isinstance(matches[0], dict) or has_service_error(matches[0]):
            raise ValueError("No unique matching TikTok embed route")
        info = matches[0].get("userInfo")
        if (not isinstance(info, dict) or has_service_error(info) or not isinstance(info.get("uniqueId"), str)
                or info["uniqueId"].casefold() != user.casefold()):
            raise ValueError("No matching TikTok user identity")
    except (TypeError, ValueError, RecursionError):
        return Result.error("Invalid or unbound TikTok embed state")
    extra = {"username": info["uniqueId"], "scope": "TikTok creator embed; not proof of ownership"}
    for key, target in (("nickname", "name"), ("signature", "bio")):
        if value := _text(info.get(key)):
            extra[target] = value
    identity = info.get("id")
    if ((type(identity) is int and identity > 0)
            or (isinstance(identity, str) and re.fullmatch(r"[0-9]+", identity) and any(c != "0" for c in identity))):
        extra["user_id"] = str(identity)
    for key, target in (("followerCount", "followers"), ("followingCount", "following"), ("heartCount", "likes")):
        if type(info.get(key)) is int and info[key] >= 0:
            extra[target] = info[key]
    for key, target in (("verified", "verified"), ("privateAccount", "private")):
        if type(info.get(key)) is bool:
            extra[target] = info[key]
    media = {}
    if avatar := _url(info.get("avatarThumbUrl")):
        media["avatar"] = avatar
    return Result.taken(extra=extra, media=media)
