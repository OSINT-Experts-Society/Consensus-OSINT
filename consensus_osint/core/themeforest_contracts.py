"""ThemeForest active profile identity and scoped metadata."""

import re
from urllib.parse import quote, urljoin

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue
from .named_user_contracts import _url


def _count(text):
    return int(text.replace(",", "")) if re.fullmatch(r"[0-9]+(?:,[0-9]{3})*", text) else None


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "style", "template", "noscript"]):
        node.decompose()
    expected = "https://themeforest.net/user/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No matching ThemeForest profile URL")
    titles = page.find_all("title")
    if len(titles) != 1 or titles[0].get_text(" ", strip=True).casefold() != f"{user}'s profile on ThemeForest".casefold():
        return Result.error("No matching ThemeForest profile title")
    extra, media = {"username": user}, {}
    headers = page.select(".user-info-header")
    if len(headers) == 1:
        header = headers[0]
        for selector, target in (("h1", "display_name"), (".user-info-header__author-level strong", "author_level")):
            nodes = header.select(selector)
            if len(nodes) == 1 and (value := nodes[0].get_text(" ", strip=True)):
                extra[target] = value
        subtitles = header.select("p.t-body.-size-m.h-p0.h-mb0")
        if len(subtitles) == 1:
            match = re.fullmatch(r"(?:(.*?),\s*)?Member since (.+)", subtitles[0].get_text(" ", strip=True))
            if match:
                extra["member_since"] = match[2]
                if match[1]:
                    extra["location"] = match[1]
        stars = header.select("span.is-visually-hidden")
        values = [m[1] for node in stars if (m := re.fullmatch(r"([0-9]+(?:\.[0-9]+)?) stars", node.get_text(strip=True)))]
        if len(values) == 1 and 0 <= float(values[0]) <= 5:
            extra["author_rating"] = values[0]
        ratings = re.findall(r"\(([0-9,]+) ratings\)", header.get_text(" ", strip=True))
        if len(ratings) == 1 and (count := _count(ratings[0])) is not None:
            extra["ratings"] = count
        sales = header.select('[itemprop="interactionCount"][content^="AuthorSales:"]')
        if len(sales) == 1 and (count := _count(sales[0]["content"].removeprefix("AuthorSales:"))) is not None:
            extra.update(sales=count, account_type="author")
        images = header.select(".user-info-header__user-profile-image-placeholder[data-src]") or header.select("img")
        if len(images) == 1:
            source = images[0].get("data-src") or images[0].get("src", "")
            if source and "default-user" not in source and (value := _url(urljoin(expected, source))):
                media["avatar"] = value
    for tab in ("followers", "following"):
        links = [node for node in page.select("a[href]") if urljoin(expected, node["href"]).casefold() == (expected + "/" + tab).casefold()]
        if len(links) == 1:
            spans = links[0].select("span")
            if len(spans) == 1 and (count := _count(spans[0].get_text(strip=True))) is not None:
                extra[tab] = count
    bios = page.select(".user-html")
    if len(bios) == 1 and (bio := bios[0].get_text(" ", strip=True)):
        extra["bio"] = bio if len(bio) <= 500 else bio[:500] + "..."
    badges = page.select(".user-info__badges")
    if len(badges) == 1:
        values = [node["data-title"] for node in badges[0].select("[data-title]") if node["data-title"].strip()]
        if values:
            extra["badges"] = "; ".join(values)
    return Result.taken(extra=extra, media=media)
