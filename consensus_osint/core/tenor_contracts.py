"""Tenor creator-page identity and safe preview metadata."""
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
    for node in page(["script", "style", "template", "noscript"]):
        node.decompose()
    titles = page.select("title")
    if len(titles) != 1:
        return Result.error("No unique Tenor profile title")
    title = titles[0].get_text().strip().replace("\u2019", "'")
    if not re.fullmatch(re.escape(user) + r"'s\s+GIFs?\s*(?:[|\-]\s*)?(?:on\s+)?Tenor", title, re.I):
        return Result.error("Tenor title does not identify the requested creator")
    expected = "https://tenor.com/users/" + quote(user, safe="")
    urls = [n.get("href", "") for n in page.select('link[rel~="canonical"]')]
    urls += [n.get("content", "") for n in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No matching Tenor profile URL")
    media = {}
    images = page.select('meta[property="og:image"]')
    if len(images) == 1 and (value := _url(images[0].get("content"))) and "tenor-logo" not in value.casefold():
        # OpenGraph can show a featured GIF rather than an avatar.
        media["preview"] = value
    return Result.taken(extra={"username": user}, media=media)
