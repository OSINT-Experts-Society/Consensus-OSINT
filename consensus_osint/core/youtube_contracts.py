"""YouTube channel metadata bound to the requested handle."""
import json
import re
from urllib.parse import unquote, urlsplit

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error
from .soundcloud_contracts import _Scripts


def _initial_data(document):
    quoted = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
    pattern = (r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted
               + r"|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*"
               + r"|(?P<assignment>(?<![\w$.])(?:ytInitialData|window\s*(?:\.\s*ytInitialData|\[\s*(?:'ytInitialData'|\"ytInitialData\")\s*\]))\s*=)")
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    states = []
    for script in _Scripts(document).scripts:
        for match in re.finditer(pattern, script):
            if match["assignment"] is None:
                continue
            start = match.end()
            while start < len(script) and script[start].isspace():
                start += 1
            data, end = decoder.raw_decode(script, start)
            tail = script[end:].lstrip()
            if tail and not tail.startswith(";"):
                raise ValueError("Unsupported YouTube state")
            states.append(data)
    if len(states) != 1 or not isinstance(states[0], dict) or has_service_error(states[0]):
        raise ValueError("Missing or ambiguous YouTube state")
    return states[0]


def _youtube_path(url):
    if not _url(url) or "\\" in url:
        return None
    try:
        parts = urlsplit(url)
        if (parts.hostname in ("www.youtube.com", "youtube.com")
                and parts.port in (None, 443 if parts.scheme == "https" else 80)
                and not parts.query and not parts.fragment):
            return unquote(parts.path).rstrip("/")
    except ValueError:
        pass
    return None


def _header_values(header, key):
    values, pending = [], [header]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if key in item:
                values.append(item[key])
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return values


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = _initial_data(response.text)
    except (TypeError, ValueError, RecursionError):
        return Result.error("Invalid or ambiguous YouTube state")
    metadata = data.get("metadata")
    meta = metadata.get("channelMetadataRenderer") if isinstance(metadata, dict) else None
    if not isinstance(meta, dict) or has_service_error(metadata) or has_service_error(meta):
        return Result.error("No successful YouTube channel metadata")
    channel_id = meta.get("externalId")
    if not isinstance(channel_id, str) or not re.fullmatch(r"UC[A-Za-z0-9_-]+", channel_id):
        return Result.error("No valid YouTube channel ID")
    if "channelUrl" in meta and _youtube_path(meta["channelUrl"]) != "/channel/" + channel_id:
        return Result.error("Conflicting YouTube channel URL")
    urls = [meta.get("vanityChannelUrl")]
    if isinstance(meta.get("ownerUrls"), list):
        urls.extend(meta["ownerUrls"])
    handles = [path[2:] for url in urls if (path := _youtube_path(url)) and path.startswith("/@")]
    header = data.get("header")
    for value in _header_values(header, "channelHandleText"):
        if isinstance(value, str) and value.startswith("@"):
            handles.append(value[1:])
    if not handles or any(handle.casefold() != user.casefold() for handle in handles):
        return Result.error("YouTube channel handle does not match the request")
    extra = {"youtube_channel_id": channel_id, "channel_url": "https://www.youtube.com/channel/" + channel_id,
             "handle": handles[0], "scope": "YouTube channel; not proof of ownership"}
    for key, target in (("title", "fullname"), ("description", "bio"), ("keywords", "keywords")):
        if value := _text(meta.get(key)):
            extra[target] = value
    media = {}
    avatar = meta.get("avatar")
    thumbs = avatar.get("thumbnails") if isinstance(avatar, dict) else None
    if isinstance(thumbs, list):
        for thumb in thumbs:
            if isinstance(thumb, dict) and (url := _url(thumb.get("url"))):
                media["image"] = url
                break
    counts = set()
    values = _header_values(header, "content")
    for value in _header_values(header, "subscriberCountText"):
        values.append(value.get("simpleText") if isinstance(value, dict) else value)
    for value in values:
        if isinstance(value, str) and re.fullmatch(r"[0-9.,]+[KMB]? subscribers?", value.strip()):
            counts.add(value.strip())
    if len(counts) == 1:
        extra["subscribers"] = counts.pop()
    return Result.taken(extra=extra, media=media)
