"""Named D3 profile pages rather than generic status or site-title evidence."""

import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "style", "template"]):
        node.decompose()
    expected = "https://d3.ru/user/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(value.rstrip("/").casefold() != expected.casefold() for value in urls):
        return Result.error("No matching D3 profile URL")
    titles = page.select("title")
    title = titles[0].get_text(" ", strip=True) if len(titles) == 1 else ""
    match = re.fullmatch(r"d3\.ru\s*[\u2014\u2013-]\s*(.+)", title, re.I)
    if not match or match[1].strip().casefold() != user.casefold():
        return Result.error("Page title does not identify the requested D3 user")
    extra = {"username": user, "name": match[1].strip()}
    for selector, key in ((".b-user_full_name", "fullname"), (".b-karma_value", "karma"), (".b-user_residence", "location"), (".b-user_subscription_text", "followers")):
        nodes = page.select(selector)
        if len(nodes) == 1 and (value := nodes[0].get_text(" ", strip=True)):
            if key != "fullname" or value.casefold() != user.casefold():
                extra[key] = value
    return Result.taken(extra=extra)
