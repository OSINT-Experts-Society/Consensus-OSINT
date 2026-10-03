"""Giphy channel pages bound to the requested public URL."""
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
    encoded = quote(user, safe="")
    expected = {f"https://giphy.com/{encoded}", f"https://giphy.com/channel/{encoded}"}
    urls = [n.get("href", "") for n in page.select('link[rel~="canonical"]')]
    urls += [n.get("content", "") for n in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/") not in expected for url in urls):
        return Result.error("No matching Giphy channel URL")
    titles = page.select("title")
    suffix = " GIFs on GIPHY - Be Animated"
    if len(titles) != 1 or not titles[0].get_text().endswith(suffix):
        return Result.error("No unique Giphy channel title")
    name = titles[0].get_text()[:-len(suffix)].strip()
    if not name:
        return Result.error("No Giphy channel name")
    extra, media = {"display_name": name}, {}
    descriptions = page.select('meta[name="description"]')
    if len(descriptions) == 1 and descriptions[0].get("content", "").strip():
        extra["bio"] = descriptions[0]["content"].strip()
    images = page.select('meta[property="og:image"]')
    if len(images) == 1 and (value := _url(images[0].get("content"))):
        media["avatar_url"] = value
    return Result.taken(extra=extra, media=media)
