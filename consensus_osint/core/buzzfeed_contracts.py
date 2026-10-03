"""BuzzFeed active Next.js profile data and independently typed metadata."""

import json
import re
from datetime import datetime, timezone
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _integer(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        return int(value)
    return None


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["style", "template", "noscript"]):
        node.decompose()
    scripts = page.select('script#__NEXT_DATA__:not([src])')
    if len(scripts) != 1:
        return Result.error("No unique active BuzzFeed page data")
    try:
        data = json.loads(scripts[0].get_text(), object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous BuzzFeed JSON")
    values = []
    current = data
    for key in ("props", "pageProps", "user"):
        if not isinstance(current, dict) or has_service_error(current):
            return Result.error("No successful BuzzFeed profile data")
        values.append(current)
        current = current.get(key)
    if not isinstance(current, dict) or not current or has_service_error(current):
        return Result.error("No coherent BuzzFeed user")
    if any(value.get("notFound") is True or value.get("__N_REDIRECT") for value in values):
        return Result.error("BuzzFeed page reports missing or redirected data")
    page_props, user_data = values[-1], current
    for key in ("username", "usernameSlug"):
        if key in user_data and (not isinstance(user_data[key], str) or user_data[key].casefold() != user.casefold()):
            return Result.error("Conflicting BuzzFeed username")
    for node in page("script"):
        node.decompose()
    expected = "https://www.buzzfeed.com/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(value.rstrip("/").casefold() != expected.casefold() for value in urls):
        return Result.error("No matching BuzzFeed profile URL")
    extra, media = {"username": user}, {}
    for source, target in (("displayName", "display_name"), ("bio", "bio")):
        if value := _text(user_data.get(source)):
            extra[target] = value
    img = _text(user_data.get("image"))
    if img:
        if img.startswith("/") and not img.startswith("//"):
            img = "https://img.buzzfeed.com/buzzfeed-static" + img
        if value := _url(img):
            media["avatar_url"] = value
    stamp = _integer(user_data.get("memberSince"))
    if stamp is not None and stamp <= 253402300799:
        try:
            extra["joined"] = datetime.fromtimestamp(stamp, tz=timezone.utc).strftime("%Y-%m-%d")
        except (ValueError, OverflowError, OSError):
            pass
    for source, target in (("points", "points"), ("buzz_count", "posts")):
        if (value := _integer(page_props.get(source))) is not None:
            extra[target] = value
    social = user_data.get("social")
    if isinstance(social, list):
        links = [url for item in social if isinstance(item, dict) and (url := _url(item.get("url")))]
        if links:
            extra["links"] = links
    return Result.taken(extra=extra, media=media)
