"""Evidence for a public Fragment username listing, not account ownership."""

import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    url = "https://fragment.com/username/" + quote(user, safe="")
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "style", "template"]):
        node.decompose()
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(value.rstrip("/").casefold() != url.casefold() for value in urls):
        return Result.error("No matching username listing URL")
    title = page.title.get_text(" ", strip=True) if page.title else ""
    heading = " ".join(node.get_text(" ", strip=True) for node in page.select("h1, .tm-section-header-text"))
    named = re.search(r"(?<![\w.-])@?" + re.escape(user) + r"(?![\w.-])", title + " " + heading, re.I)
    statuses = page.select(".tm-section-header-status")
    if (not named or "fragment" not in title.casefold() or len(statuses) != 1
            or re.search(r"not found|access denied|unavailable", title + " " + heading, re.I)):
        return Result.error("No unambiguous named username listing")
    status = statuses[0].get_text(" ", strip=True)
    if not status:
        return Result.error("No listing status")
    extra = {"username": user, "status": status,
             "scope": "Public Fragment username listing; not proof of a Telegram account or ownership"}
    prices = page.select(".table-cell-value.tm-value")
    if len(prices) == 1:
        value = prices[0].get_text(" ", strip=True)
        if re.fullmatch(r"[0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?", value):
            extra["price_ton"] = value
    return Result.taken(extra=extra)
