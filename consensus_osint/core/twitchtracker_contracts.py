"""Query-bound TwitchTracker listings, without inferring Twitch account absence."""

import re
from urllib.parse import quote, urlsplit

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
    expected = "https://twitchtracker.com/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No matching TwitchTracker listing URL")
    title = page.title.get_text(" ", strip=True) if page.title else ""
    headings = " ".join(node.get_text(" ", strip=True) for node in page.select("h1"))
    named = re.search(r"(?<![\w.-])" + re.escape(user) + r"(?![\w.-])", title + " " + headings, re.I)
    if (not named or "streamer overview" not in title.casefold()
            or re.search(r"not found|access denied|unavailable", title + " " + headings, re.I)):
        return Result.error("No named streamer overview")
    extra, media = {"username": user, "title": title,
                    "scope": "Public TwitchTracker listing; not verification of a current Twitch account"}, {}
    for label, key in (("RANK", "rank"), ("FOLLOWERS", "followers")):
        values = []
        for node in page.find_all("div"):
            if node.get_text(" ", strip=True).upper() != label:
                continue
            previous = node.find_previous_sibling("div")
            if previous:
                raw = previous.get_text(" ", strip=True)
                if re.fullmatch(r"#?[0-9]+(?:,[0-9]{3})*", raw) and len(raw) <= 30:
                    values.append(raw.lstrip("#").replace(",", ""))
        if len(values) == 1:
            extra[key] = values[0]
    images = []
    for node in page.select("img[src]"):
        value = _url(node.get("src"))
        if value:
            parsed = urlsplit(value)
            if parsed.hostname == "static-cdn.jtvnw.net" and parsed.path.startswith("/jtv_user_pictures/"):
                images.append(value)
    if len(set(images)) == 1:
        media["avatar"] = images[0]
    return Result.taken(extra=extra, media=media)
