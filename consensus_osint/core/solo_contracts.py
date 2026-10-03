"""Solo.to profile titles require matching active profile URLs."""

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
    expected = "https://solo.to/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No matching Solo.to profile URL")
    titles = page.find_all("title")
    title = titles[0].get_text(" ", strip=True) if len(titles) == 1 else ""
    match = re.fullmatch(r"(.+?)\s+(?:\u00b7|\|)\s+solo\.to", title, re.I)
    if not match or match.group(1).strip().casefold() in ("not found", "page not found", "404", "error"):
        return Result.error("No unique Solo.to profile title")
    extra, media = {"username": user, "name": match.group(1).strip()}, {}
    images = page.select('meta[property="og:image"]')
    if len(images) == 1 and (value := _url(images[0].get("content"))):
        if "solo-logo" not in value.casefold():
            media["avatar"] = value
    return Result.taken(extra=extra, media=media)
