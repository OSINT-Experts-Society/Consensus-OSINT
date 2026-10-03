"""35photo profile evidence bound to the requested public profile URL."""

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
    expected = "https://35photo.pro/@" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    headings = page.select("h1.thinFont")
    markers = page.select('span[title^="Total photos"]')
    if (not urls or any(value.rstrip("/").casefold() != expected.casefold() for value in urls)
            or len(headings) != 1 or not headings[0].get_text(" ", strip=True) or len(markers) != 1):
        return Result.error("No unambiguous requested 35photo profile")
    title = page.title.get_text(" ", strip=True) if page.title else ""
    if re.search(r"not found|access denied|unavailable", title, re.I):
        return Result.error("Profile page reports missing or unavailable content")
    extra, media = {"username": user, "name": headings[0].get_text(" ", strip=True)}, {}
    for prefix, key in (("Photographers from the city of ", "city"), ("Photographers from ", "country")):
        values = [node.get("title")[len(prefix):].strip() for node in page.select("[title]")
                  if node.get("title", "").startswith(prefix) and not (key == "country" and node.get("title", "").startswith("Photographers from the city of "))]
        if len(values) == 1 and values[0]:
            extra[key] = values[0]
    count = markers[0].get_text(" ", strip=True)
    if re.fullmatch(r"[0-9]{1,20}", count):
        extra["photos"] = int(count)
    avatars = page.select("img.avatar140[src]")
    if len(avatars) == 1 and (value := _url(avatars[0].get("src"))):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
