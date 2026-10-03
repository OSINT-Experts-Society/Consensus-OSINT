"""Query-bound creator page evidence for Donatello and Ko-fi."""

import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue
from .named_user_contracts import _url


def result(response, site, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    host = "donatello.to" if site == "donatello" else "ko-fi.com"
    expected = f"https://{host}/" + quote(user, safe="")
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "style", "template"]):
        node.decompose()
    declared = [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    declared += [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    if not declared or any(url.rstrip("/").casefold() != expected.casefold() for url in declared):
        return Result.error("No matching creator profile URL")
    extra, media = {"username": user}, {}
    if site == "donatello":
        authors = [node.get("content", "").strip() for node in page.select('meta[name="author"]')]
        if len(authors) == 1 and authors[0] and authors[0].casefold() != user.casefold():
            extra["name"] = authors[0]
        return Result.taken(extra=extra)
    names = page.select("#displayName")
    if len(names) != 1:
        return Result.error("No unambiguous creator display name")
    if value := names[0].get_text(" ", strip=True):
        extra["name"] = value
    identifiers = {node.get("data-reported-page-id") for node in page.select("[data-reported-page-id]")}
    if len(identifiers) == 1 and (value := next(iter(identifiers))):
        extra["id"] = value
    for node in page.select('[class*="kfds-c-profile-link-handle"]'):
        match = re.fullmatch(r"([\d,]+)\s+(Followers|Supporters)", node.get_text(" ", strip=True), re.I)
        if match:
            digits = match[1].replace(",", "")
            if digits.isdigit() and len(digits) < 20:
                extra[match[2].lower()] = int(digits)
    bios = page.select("#expanded-page > p")
    if len(bios) == 1 and (value := bios[0].get_text(" ", strip=True)):
        extra["bio"] = value
    for selector, target in (("span.label-tag", "categories"), (".kfds-c-profile-tab-box label", "features")):
        values = list(dict.fromkeys(value for node in page.select(selector) if (value := node.get_text(" ", strip=True))))
        if values:
            extra[target] = values
    links = list(dict.fromkeys(value for node in page.select('a[id^="socialLink_"], .social-link a')
                              if (value := _url(node.get("href")))))
    if links:
        extra["links"] = links
    pictures = page.select("img#profilePicture")
    if len(pictures) == 1 and (value := _url(pictures[0].get("src"))):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
