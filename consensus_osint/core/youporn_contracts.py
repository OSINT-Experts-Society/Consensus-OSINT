"""YouPorn public page evidence; absence is not signup availability."""
import re
from urllib.parse import quote, unquote, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue
from .named_user_contracts import _url

BASE_URL = "https://www.youporn.com"


def page_path(namespace, user):
    return "/" + namespace + "/" + quote(user, safe="") + "/"


def trusted_url(raw):
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return None
    try:
        parsed = urlsplit(raw)
        if (parsed.scheme != "https" or parsed.query or parsed.fragment
                or not re.fullmatch(r"(?:www|[a-z]{2})\.youporn\.com", parsed.netloc)):
            return None
        return parsed
    except ValueError:
        return None


def redirect_target(raw, namespace, user):
    parsed = trusted_url(raw)
    return raw if parsed and parsed.path == page_path(namespace, user) else None


def result(response, user, namespace):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    links, names = soup.select('link[rel~="canonical"]'), soup.select('h1.name-title')
    if len(links) != 1 or len(names) != 1:
        return Result.error("No unique YouPorn canonical and profile heading")
    parsed = trusted_url(links[0].get("href"))
    name = names[0].get_text(" ", strip=True)
    if parsed is None or not name or not user:
        return Result.error("Invalid YouPorn profile identity")
    extra = {"name": name}
    if namespace == "uservids":
        identity = re.fullmatch(r"/user/([1-9][0-9]*)/?", parsed.path)
        if identity is None or name.casefold() != user.casefold():
            return Result.error("YouPorn viewer identity does not match requested handle")
        extra.update(username=name, user_id=identity[1], type="viewer")
    else:
        if unquote(parsed.path).rstrip("/").casefold() != ("/" + namespace + "/" + user).casefold():
            return Result.error("YouPorn canonical does not match requested page")
        extra["type"] = {"pornstar": "model", "amateur": "amateur", "channel": "channel"}[namespace]
    extra["scope"] = "YouPorn public page; not proof of signup availability or ownership"
    values = {}
    for label in soup.select('p.info-stat-label'):
        value = label.find_next_sibling()
        if value is None or value.name != "p" or "info-stat-data" not in value.get("class", []):
            continue
        key = label.get_text(" ", strip=True).lower().replace(" ", "_")
        text = value.get_text(" ", strip=True)
        if key and text and key not in {"name", "username", "user_id", "type", "scope", "media"} and not key.startswith("_"):
            values.setdefault(key, []).append(text)
    extra.update({key: items[0] for key, items in values.items() if len(items) == 1})
    avatars = soup.select('div.avatar-wrapper img[data-src]')
    media = {}
    if len(avatars) == 1:
        raw = avatars[0].get("data-src")
        avatar = _url(raw) if isinstance(raw, str) and "\\" not in raw else None
        if avatar:
            media["avatar"] = avatar
    return Result.taken(extra=extra, media=media)
