"""Pastebin profile evidence bound to the requested profile URL."""

import re
from urllib.parse import quote, urljoin

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
    expected = "https://pastebin.com/u/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No matching Pastebin profile URL")
    profiles = page.select(".user-view")
    if len(profiles) != 1:
        return Result.error("No unique active Pastebin profile container")
    profile = profiles[0]
    if not profile.select(".user-icon, .info-bar"):
        return Result.error("No profile details in the Pastebin container")
    extra, media = {"username": user}, {}
    images = profile.select(".user-icon img[src]")
    if len(images) == 1:
        value = _url(urljoin("https://pastebin.com/", images[0]["src"]))
        if value and "guest.png" not in value.casefold():
            media["avatar"] = value
    if profile.select(".pro"):
        extra["pro_user"] = True
    for all_views, target in ((False, "views"), (True, "all_views")):
        nodes = [n for n in profile.select("span.views") if ("-all" in n.get("class", [])) == all_views]
        if len(nodes) == 1:
            value = nodes[0].get_text(strip=True)
            if re.fullmatch(r"[0-9]+(?:,[0-9]{3})*", value):
                extra[target] = int(value.replace(",", ""))
    for selector, target in (("span.rating", "rating"), ("span.location", "location")):
        nodes = profile.select(selector)
        if len(nodes) == 1 and (value := nodes[0].get_text(" ", strip=True)):
            extra[target] = value
    dates = profile.select(".date-text[title]")
    if len(dates) == 1 and dates[0]["title"].strip():
        extra["joined"] = dates[0]["title"].strip()
    links = profile.select("a.web[href]")
    if len(links) == 1 and (value := _url(links[0]["href"])):
        extra["website"] = value
    return Result.taken(extra=extra, media=media)
