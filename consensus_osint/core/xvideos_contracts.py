"""XVideos profile identity from complete active embedded JSON objects."""
import json
import re
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error
from .soundcloud_contracts import _Scripts


def _users(document):
    # Read complete JSON object literals in active scripts; skip comments and
    # quoted examples. A candidate must directly contain the page's user field.
    quoted = r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`"
    token = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted
                       + r"|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*|(?P<object>\{)|(?P<close>\})")
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    candidates = []
    for script in _Scripts(document).scripts:
        offset = 0
        while match := token.search(script, offset):
            offset = match.end()
            if match["object"] is None:
                continue
            try:
                state, end = decoder.raw_decode(script, match.start())
            except ValueError:
                # Never recover evidence from inside an invalid JSON object or
                # a JavaScript block (which may be an unexecuted function).
                # The same lexer excludes braces in strings/comments/regexes.
                depth = 1
                while depth and (nested := token.search(script, offset)):
                    offset = nested.end()
                    if nested["object"] is not None:
                        depth += 1
                    elif nested["close"] is not None:
                        depth -= 1
                if depth:
                    break
                continue
            offset = end
            if isinstance(state, dict) and "user" in state:
                if has_service_error(state):
                    raise ValueError("Failed XVideos state")
                candidates.append(state["user"])
    if len(candidates) != 1 or not isinstance(candidates[0], dict) or has_service_error(candidates[0]):
        raise ValueError("No unique successful XVideos user object")
    return candidates[0]


VARIANTS = {
    "profile": ("www.xvideos.com", "/profiles/", ("Profile",)),
    "xvideos-pornstars": ("www.xvideos.com", "/pornstars/", ("Channel", "Model")),
    "xvideos-users-channels": ("www.xvideos.com", "/", ("Channel",)),
    "xvideosmodels": ("www.xvideos.com", "/models/", ("Model", "Channel")),
    "xvideos-red": ("www.xvideos.red", "/", ("Channel", "Model", "Profile")),
}


def _route(raw, user, variant="profile"):
    host, prefix, _ = VARIANTS[variant]
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return False
    try:
        parsed = urlsplit(raw)
        return (parsed.scheme in ("", "https") and parsed.netloc in ("", host)
                and not parsed.query and not parsed.fragment
                and unquote(parsed.path).rstrip("/").casefold() == (prefix + user).casefold())
    except ValueError:
        return False


def result(response, query, variant="profile"):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        user = _users(response.text)
    except (TypeError, ValueError):
        return Result.error("No unambiguous active XVideos profile state")
    if (not isinstance(user.get("username"), str) or not user["username"]
            or user["username"].casefold() != query.casefold() or not _route(user.get("url"), query, variant)
            or type(user.get("id_user")) is not int or user["id_user"] <= 0):
        return Result.error("XVideos user identity does not match requested profile")
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    canonicals = soup.select('link[rel~="canonical"]')
    if any(not _route(node.get("href"), query, variant) for node in canonicals):
        return Result.error("Conflicting XVideos canonical profile URL")
    titles = soup.select('title')
    display = _text(user.get("display"))
    allowed = {query.casefold()}
    if display:
        allowed.add(display.casefold())
    if len(titles) != 1:
        return Result.error("No unique XVideos profile title")
    title = titles[0].get_text(" ", strip=True)
    host, _, pages = VARIANTS[variant]
    brand = r"XVIDEOS\.COM" if host == "www.xvideos.com" else r"(?:XVIDEOS\.RED|XVIDEOS RED|XVIDEOS\.COM)"
    match = re.fullmatch(r"(.+) - (?:" + "|".join(pages) + r") page - " + brand, title, re.IGNORECASE)
    if match is None or match[1].casefold() not in allowed:
        return Result.error("XVideos profile title does not match returned identity")
    extra, media = {"username": user["username"], "user_id": user["id_user"]}, {}
    if variant != "profile":
        extra["scope"] = "XVideos public creator page; not proof of a same-named member account or ownership"
    if display:
        extra["name"] = display
    for key in ("profile_picture", "profile_picture_small"):
        avatar = user.get(key)
        if isinstance(avatar, str) and "\\" not in avatar and _url(avatar):
            media["avatar"] = avatar
            break
    fields = {}
    reserved = {"username", "user_id", "name", "media", "scope"}
    for row in soup.select('p[id^="pinfo-"]'):
        labels, values = row.select('strong'), row.select('span')
        if len(labels) != 1 or len(values) != 1:
            continue
        key = labels[0].get_text(" ", strip=True).rstrip(":").strip().casefold().replace(" ", "_")
        value = values[0].get_text(" ", strip=True)
        if key and key not in reserved and not key.startswith("_") and value and value.casefold() != "display":
            fields.setdefault(key, []).append(value)
    extra.update({key: values[0] for key, values in fields.items() if len(values) == 1})
    return Result.taken(extra=extra, media=media)
