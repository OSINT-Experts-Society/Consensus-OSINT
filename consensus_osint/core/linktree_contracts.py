"""Coherent Linktree profile data rather than canonical or blocked-page echoes."""

import json
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["style", "template"]):
        node.decompose()
    scripts = page.select("script#__NEXT_DATA__")
    if len(scripts) != 1 or scripts[0].has_attr("src"):
        return Result.error("No unique embedded Linktree profile")
    try:
        data = json.loads(scripts[0].get_text(), object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data) or data.get("page") in ("/_error", "/status/blocked", "/404"):
        return Result.error("No coherent Linktree profile response")
    props = data.get("props")
    pp = props.get("pageProps") if isinstance(props, dict) else None
    if not isinstance(pp, dict) or has_service_error(props) or has_service_error(pp) or pp.get("statusCode", 200) != 200:
        return Result.error("No successful profile payload")
    account = pp.get("account", {})
    if not isinstance(account, dict) or has_service_error(account):
        return Result.error("Invalid account payload")
    names = [obj["username"] for obj in (pp, account) if "username" in obj]
    if not names or any(not isinstance(value, str) or value.casefold() != user.casefold() for value in names):
        return Result.error("Profile usernames do not identify the requested handle")
    if not account and not _text(pp.get("pageTitle")) and not isinstance(pp.get("links"), list):
        return Result.error("No profile content accompanying username")
    for node in page("script"):
        node.decompose()
    expected = "https://linktr.ee/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if any(value.rstrip("/").casefold() != expected.casefold() for value in urls):
        return Result.error("Conflicting Linktree profile URL")
    extra, media = {"username": names[0]}, {}
    for source, target in (("pageTitle", "name"), ("description", "description")):
        if value := _text(pp.get(source)) or _text(account.get(source)):
            extra[target] = value
    if value := _url(account.get("profilePictureUrl")) or _url(pp.get("customAvatar")):
        media["avatar"] = value
    if type(pp.get("isProfileVerified")) is bool:
        extra["verified"] = pp["isProfileVerified"]
    for source, target, label in (("links", "showcased_links", "title"), ("socialLinks", "social_links", "platform")):
        links = pp.get(source)
        if isinstance(links, list):
            values = []
            for link in links:
                if isinstance(link, dict) and (url := _url(link.get("url"))):
                    title = _text(link.get(label))
                    values.append(f"{title}: {url}" if title else url)
            if values:
                extra[target] = values
    return Result.taken(extra=extra, media=media)
