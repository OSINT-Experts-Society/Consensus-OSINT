"""XNXX username availability and independently confirmed public profiles."""
import html
import json
import re
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error
from .xvideos_contracts import _users

SCOPE = "Username availability; not proof of a current XNXX public profile or ownership"


def availability(response, query):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid XNXX availability JSON")
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No successful XNXX availability envelope")
    if "profile" in data and data["profile"] != query:
        return Result.error("XNXX availability identifies another profile name")
    message = data.get("message", "")
    if not isinstance(message, str):
        return Result.error("Malformed XNXX validation message")
    message = html.unescape(message).strip()
    if data.get("result") is True and not message and (data.get("code") is None or type(data["code"]) is int and data["code"] == 0):
        return Result.available(extra={"available": True, "scope": SCOPE})
    if (data.get("result") is False and type(data.get("code")) is int and data["code"] == 1
            and re.fullmatch(r"(?:(?:this )?(?:profile name|username|name) )?already exists\.?", message, re.IGNORECASE)):
        return Result.taken(extra={"available": False, "scope": SCOPE})
    return Result.error("No consistent XNXX username availability result")


def _namespace(raw, query):
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return None
    try:
        parsed = urlsplit(raw)
        if parsed.scheme not in ("", "https") or parsed.netloc not in ("", "www.xnxx.com") or parsed.query or parsed.fragment:
            return None
        path = unquote(parsed.path).rstrip("/")
        for namespace in ("pornstar", "porn-maker", "profile"):
            if path.casefold() == ("/" + namespace + "/" + query).casefold():
                return namespace
    except ValueError:
        pass
    return None


def public_profile(response, query):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        user = _users(response.text)
    except (TypeError, ValueError):
        return Result.error("No unique active XNXX user object")
    namespace = _namespace(user.get("url"), query)
    if (not namespace or not isinstance(user.get("username"), str) or not user["username"]
            or user["username"].casefold() != query.casefold()
            or type(user.get("id_user")) is not int or user["id_user"] <= 0):
        return Result.error("XNXX public user identity does not match")
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    if any(_namespace(node.get("href"), query) != namespace for node in soup.select('link[rel~="canonical"]')):
        return Result.error("XNXX canonical conflicts with public user")
    extra = {"username": user["username"], "user_id": user["id_user"], "profile_confirmed": True,
             "type": {"pornstar": "model", "porn-maker": "porn_maker", "profile": "public_profile"}[namespace]}
    for key, target in (("display", "name"), ("sex", "gender")):
        if value := _text(user.get(key)):
            extra[target] = value
    media = {}
    for key in ("profile_picture", "profile_picture_small"):
        value = user.get(key)
        if isinstance(value, str) and "\\" not in value and _url(value):
            media["avatar"] = value
            break
    descriptions = soup.select('meta[name="description"]')
    if len(descriptions) == 1 and isinstance(descriptions[0].get("content"), str):
        names, separator, _ = descriptions[0]["content"].partition(",free videos")
        if separator:
            aliases = list(dict.fromkeys(name.strip() for name in names.split(",")
                                         if name.strip() and name.strip().casefold() != extra.get("name", "").casefold()))
            if aliases:
                extra["aliases"] = ", ".join(aliases)
    return Result.taken(extra=extra, media=media)
