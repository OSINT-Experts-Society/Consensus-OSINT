"""Product Hunt profile title and full profile URL must agree."""

import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue


def valid_user(user):
    return isinstance(user, str) and re.fullmatch(r"[a-zA-Z0-9_]{2,32}", user) is not None


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "template", "style"]):
        node.decompose()
    expected = "https://www.producthunt.com/@" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No unambiguous Product Hunt profile URL")
    titles = page.find_all("title")
    title = titles[0].get_text(" ", strip=True) if len(titles) == 1 else ""
    match = re.fullmatch(r"(.+?)(?:'s|\u2019s) profile on Product Hunt", title)
    if not match:
        return Result.error("No unique Product Hunt profile title")
    return Result.taken(extra={"username": user, "name": match.group(1).strip()})
