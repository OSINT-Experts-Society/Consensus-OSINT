"""Query-bound Threads profile evidence; login/redirect pages stay inconclusive."""
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url


def valid_user(user):
    return isinstance(user, str) and re.fullmatch(r"[A-Za-z0-9._]{1,30}", user) is not None


def result(response, user):
    if not valid_user(user):
        return Result.error("Invalid Threads username")
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    urls = [node.get("href") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content") for node in page.select('meta[property="og:url"]')]
    if not urls:
        return Result.error("No Threads profile identity")
    for url in urls:
        try:
            parts = urlsplit(url) if _url(url) and "\\" not in url else None
            if (parts is None or parts.scheme != "https" or parts.username or parts.password
                    or parts.hostname not in ("threads.net", "www.threads.net", "threads.com", "www.threads.com")
                    or parts.port not in (None, 443) or parts.query or parts.fragment
                    or parts.path.rstrip("/").casefold() != "/@" + user.casefold()):
                return Result.error("Conflicting Threads profile identity")
        except ValueError:
            return Result.error("Invalid Threads profile URL")
    titles = [node.get("content", "") for node in page.select('meta[property="og:title"]')]
    names = []
    for title in titles:
        match = re.match(r"^(.*?)\s*\(@" + re.escape(user) + r"\)(?:\s|$)", title, re.I)
        if not match or not _text(match[1]):
            return Result.error("No named Threads profile evidence")
        names.append(match[1].strip())
    if not names or len(set(names)) != 1:
        return Result.error("Missing or ambiguous Threads profile title")
    extra, media = {"username": user, "name": names[0]}, {}
    descriptions = [node.get("content") for node in page.select('meta[property="og:description"]')]
    if len(descriptions) == 1 and _text(descriptions[0]):
        extra["description"] = descriptions[0]
    avatars = [node.get("content") for node in page.select('meta[property="og:image"]')]
    if len(avatars) == 1 and _url(avatars[0]) and "rsrc.php" not in avatars[0]:
        media["avatar"] = avatars[0]
    return Result.taken(extra=extra, media=media)
