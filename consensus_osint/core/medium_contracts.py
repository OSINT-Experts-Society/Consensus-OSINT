"""Medium response evidence without generic missing-page or redirect verdicts."""

import json
from datetime import datetime, timezone
from urllib.parse import quote
from xml.etree import ElementTree

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error

JSON_GUARD = ")]}while(1);</x>"


def result(response, user, kind):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    expected = "https://medium.com/@" + quote(user, safe="")
    extra, media = {"username": user}, {}
    if kind == "json":
        body = response.text.lstrip()
        if not body.startswith(JSON_GUARD):
            return Result.error("Missing Medium JSON guard")
        try:
            data = json.loads(body[len(JSON_GUARD):], object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return Result.error("Invalid Medium JSON")
        if not isinstance(data, dict) or has_service_error(data):
            return Result.error("No successful Medium profile response")
        payload = data.get("payload")
        profile = payload.get("user") if isinstance(payload, dict) else None
        if (not isinstance(profile, dict) or has_service_error(payload) or has_service_error(profile)
                or not isinstance(profile.get("username"), str) or profile["username"].casefold() != user.casefold()):
            return Result.error("No matching Medium user")
        for target, field in (("fullname", "name"), ("bio", "bio"), ("twitter", "twitterScreenName"), ("id", "userId")):
            if value := _text(profile.get(field)):
                extra[target] = value
        created = profile.get("createdAt")
        if type(created) in (int, float) and 0 <= created <= 253402300799000:
            try:
                extra["joined"] = datetime.fromtimestamp(created / 1000, timezone.utc).date().isoformat()
            except (ValueError, OSError, OverflowError):
                pass
        refs = payload.get("references")
        stats = refs.get("SocialStats") if isinstance(refs, dict) else None
        stats = stats.get(extra.get("id")) if isinstance(stats, dict) else None
        if isinstance(stats, dict) and not has_service_error(stats):
            for target, field in (("followers", "usersFollowedByCount"), ("following", "usersFollowedCount")):
                if type(stats.get(field)) is int and stats[field] >= 0:
                    extra[target] = stats[field]
        if value := _text(profile.get("imageId")):
            media["avatar"] = "https://miro.medium.com/v2/resize:fit:2400/" + quote(value, safe="")
    elif kind in ("html", "html_about"):
        page = BeautifulSoup(response.text, "html.parser")
        for node in page(["template", "style"]):
            node.decompose()
        people = []
        for node in page.select('script[type="application/ld+json"]:not([src])'):
            try:
                data = json.loads(node.get_text(), object_pairs_hook=_unique_object)
            except (TypeError, ValueError):
                continue
            if isinstance(data, dict) and data.get("@type") == "Person" and not has_service_error(data):
                if isinstance(data.get("url"), str) and data["url"].rstrip("/").casefold() == expected.casefold():
                    people.append(data)
        for node in page("script"):
            node.decompose()
        names = [node.get("content", "") for node in page.select('meta[property="profile:username"]')]
        if not names or any(name.casefold() != user.casefold() for name in names):
            return Result.error("No matching Medium profile metadata")
        urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
        urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
        allowed_urls = {expected.casefold()}
        if kind == "html_about":
            allowed_urls.add(expected.casefold() + "/about")
        if any(url.rstrip("/").casefold() not in allowed_urls for url in urls):
            return Result.error("Conflicting Medium profile URL")
        if len(people) == 1:
            for source, target in (("name", "fullname"), ("description", "bio")):
                if value := _text(people[0].get(source)):
                    extra[target] = value
        images = page.select('meta[property="og:image"]')
        if len(images) == 1 and (value := _url(images[0].get("content"))):
            media["avatar"] = value
        followers = [node.get_text(" ", strip=True) for node in page.select("a[href]") if node["href"].split("?", 1)[0] == "/@" + user + "/followers"]
        if len(followers) == 1 and followers[0].endswith(" followers"):
            extra["followers"] = followers[0].removesuffix(" followers")
    elif kind == "feed":
        if "<!DOCTYPE" in response.text.upper() or "<!ENTITY" in response.text.upper():
            return Result.error("Unsupported feed declarations")
        try:
            root = ElementTree.fromstring(response.text)
        except ElementTree.ParseError:
            return Result.error("Invalid Medium feed")
        channels = root.findall("channel") if root.tag == "rss" else []
        if len(channels) != 1:
            return Result.error("No unique RSS channel")
        channel = channels[0]
        links = channel.findall("link")
        if len(links) != 1 or (links[0].text or "").split("?", 1)[0].rstrip("/").casefold() != expected.casefold():
            return Result.error("Feed channel does not identify requested user")
        title = channel.findtext("title") or ""
        if title.startswith("Stories by ") and title.endswith(" on Medium"):
            extra["fullname"] = title[len("Stories by "):-len(" on Medium")]
        if value := _url(channel.findtext("image/url")):
            media["avatar"] = value
    else:
        return Result.error("Unsupported Medium view")
    return Result.taken(extra=extra, media=media)
