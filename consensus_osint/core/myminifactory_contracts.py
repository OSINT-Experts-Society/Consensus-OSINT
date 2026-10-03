"""Named MyMiniFactory profile pages with safe optional metadata."""

import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue
from .named_user_contracts import _url


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "style", "template"]):
        node.decompose()
    expected = "https://www.myminifactory.com/users/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(value.rstrip("/").casefold() != expected.casefold() for value in urls):
        return Result.error("No matching MyMiniFactory profile URL")
    titles = page.select("title")
    title = titles[0].get_text(" ", strip=True) if len(titles) == 1 else ""
    match = re.fullmatch(r"(.*?)\s*@" + re.escape(user) + r"\s*-\s*MyMiniFactory", title, re.I)
    if not match or re.search(r"not found|access denied|unavailable", title, re.I):
        return Result.error("No named MyMiniFactory profile title")
    extra, media = {"username": user, "title": title}, {}
    if name := match[1].strip():
        extra["name"] = name
    descriptions = page.select('meta[name="description"]')
    if len(descriptions) == 1 and (value := descriptions[0].get("content", "").strip()):
        extra["bio"] = value
    images = page.select('meta[property="og:image"]')
    if len(images) == 1 and (value := _url(images[0].get("content"))):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
