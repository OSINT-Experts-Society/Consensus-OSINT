"""Bound public developer page evidence; page absence is not account absence."""

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
    url = f"https://{site}.com/" + quote(user, safe="")
    if site == "wordpress":
        url = "https://profiles.wordpress.org/" + quote(user, safe="")
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "style", "template"]):
        node.decompose()
    declarations = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    declarations += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not declarations or any(value.rstrip("/").casefold() != url.casefold() for value in declarations):
        return Result.error("No matching profile URL declaration")
    usernames = [node.get("content", "") for node in page.select('meta[property="profile:username"]')]
    if usernames and any(value.casefold() != user.casefold() for value in usernames):
        return Result.error("Conflicting profile username")
    title = page.title.get_text(" ", strip=True) if page.title else ""
    heading = " ".join(node.get_text(" ", strip=True) for node in page.select("h1"))
    if re.search(r"page not found|user not found|access denied|service unavailable", title + " " + heading, re.I):
        return Result.error("Profile page reports missing or unavailable content")
    named = bool(re.search(r"(?<![\w.-])" + re.escape(user) + r"(?![\w.-])", title + " " + heading, re.I))
    if site == "wordpress":
        bound = "user profile" in title.casefold() and (bool(usernames) or named)
    elif site == "devpost":
        bound = "software portfolio" in title.casefold() and (bool(usernames) or named)
    else:
        profile_types = [node.get("content", "").casefold() for node in page.select('meta[property="og:type"]')]
        bound = bool(usernames) or (profile_types == ["profile"] and named and "hackerone" in title.casefold())
    if not bound:
        return Result.error("No unambiguous named public profile evidence")
    extra, media = {"username": user}, {}
    if site == "wordpress":
        names = page.select(".user-name")
        if len(names) == 1 and (name := names[0].get_text(" ", strip=True)):
            extra["name"] = name
    elif site == "devpost":
        match = re.match(r"(.+?)[?']s\s*\(" + re.escape(user) + r"\)", title, re.I)
        if match:
            extra["name"] = match.group(1).strip()
        images = [node.get("content", "") for node in page.select('meta[property="og:image"]')]
        if len(images) == 1 and (value := _url(images[0])) and "default-avatar" not in value.lower():
            media["avatar"] = value
    else:
        descriptions = [node.get("content", "").strip() for node in page.select('meta[property="og:description"]')]
        if len(descriptions) == 1 and descriptions[0] and descriptions[0] != "-":
            extra["bio"] = descriptions[0]
    return Result.taken(extra=extra, media=media)
