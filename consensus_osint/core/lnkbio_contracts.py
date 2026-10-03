"""Require an active Lnk.Bio profile bound to the requested username."""

from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "style", "template"]):
        node.decompose()
    profiles = page.select('div.public-container-inner[data-page-id^="PAGE_"]')
    if len(profiles) != 1:
        return Result.error("No unique active Lnk.Bio profile")
    profile = profiles[0]
    names = [node.get_text(" ", strip=True).removeprefix("@") for node in profile.select("a.pb-username")]
    if profile.has_attr("data-username"):
        names.append(profile["data-username"])
    if not names or any(name.casefold() != user.casefold() for name in names):
        return Result.error("Profile does not identify the requested username")
    expected = "https://lnk.bio/" + quote(user, safe="")
    declarations = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    declarations += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if any(value.rstrip("/").casefold() != expected.casefold() for value in declarations):
        return Result.error("Conflicting profile URL")
    extra, media = {"username": user}, {}
    for selector, key in ((".pb-name", "name"), (".pb-bio", "bio")):
        values = [node.get_text(" ", strip=True) for node in profile.select(selector)]
        if values and (key == "bio" or len(values) == 1):
            if value := " ".join(x for x in values if x):
                extra[key] = value
    images = profile.select("img#profile_picture_catch_error")
    if len(images) == 1 and (value := _url(images[0].get("src"))):
        media["avatar"] = value
    anchors = profile.select("a.pb-username")
    if len(anchors) == 1:
        anchor = anchors[0]
        for attribute, key in (("data-id", "uid"), ("data-timezone", "timezone")):
            if value := _text(anchor.get(attribute)):
                extra[key] = value
        if value := _url(anchor.get("href")):
            extra["profile_url"] = value
    if value := _url(profile.get("data-page-url")):
        if not value.casefold().startswith(("https://lnk.bio/", "http://lnk.bio/")):
            extra["custom_domain"] = value
    if profile.select('[title="Verified by Lnk.Bio"], [aria-label="Verified by Lnk.Bio"]'):
        extra["verified"] = True
    links = [url for node in profile.select("a.lb-icon-pub[href]") if (url := _url(node.get("href")))]
    if links:
        extra["social_links"] = links
    return Result.taken(extra=extra, media=media)
