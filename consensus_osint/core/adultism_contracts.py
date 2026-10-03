"""Adultism profile-section boundaries and optional metadata."""
import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url

BASE_URL = "https://www.adultism.com"


def _document(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        raise ValueError(reason)
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    sections = soup.select('section#spr')
    if len(sections) != 1 or sections[0].get("itemtype") not in ("http://schema.org/Person", "https://schema.org/Person"):
        raise ValueError("No unique Adultism profile section")
    section = sections[0]
    headings = section.select('h1.nick[itemprop="name"]')
    name = headings[0].get_text(" ", strip=True) if len(headings) == 1 else ""
    if not name or name.casefold() != user.casefold():
        raise ValueError("Adultism profile heading does not match")
    return soup, section, name


def _decimal(value):
    return value if isinstance(value, str) and re.fullmatch(r"[0-9]+", value) else None


def _media_url(raw):
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return None
    try:
        return _url(urljoin(BASE_URL, raw))
    except ValueError:
        return None


def result(response, user):
    try:
        _, section, name = _document(response, user)
    except ValueError as exc:
        return Result.error(str(exc))
    extra, media = {"name": name}, {}
    if identity := _decimal(section.get("data-channel-id")):
        extra["channel_id"] = identity
    subscribers = section.select('.cm-value.subscriber-count[data-canonical]')
    if len(subscribers) == 1 and (value := _decimal(subscribers[0].get("data-canonical"))):
        extra["subscribers"] = value
    badges = [_text(node.get("title")) for node in section.select('.pc-badge[title]')]
    if any(badges):
        extra["badges"] = ", ".join(value for value in badges if value)
    for key, prop in (("birthdate", "birthDate"), ("gender", "gender")):
        nodes = section.select('meta[itemprop="' + prop + '"]')
        if len(nodes) == 1 and (value := _text(nodes[0].get("content"))):
            extra[key] = value
    reserved = {"name", "channel_id", "subscribers", "badges", "birthdate", "gender", "interests", "comments", "friends", "media", "avatar", "avatar_full"}
    rows = {}
    for row in section.select('div.row'):
        labels, values = row.select('span.label'), row.select('span.value')
        if len(labels) == len(values) == 1:
            label, value = labels[0].get_text(" ", strip=True), values[0].get_text(" ", strip=True)
            key = label.casefold()
            if label and value and key not in reserved and not label.startswith("_"):
                rows.setdefault(key, []).append(value)
    extra.update({key: values[0] for key, values in rows.items() if len(values) == 1})
    descriptions = section.select('div[itemprop="description"]')
    if len(descriptions) == 1 and (value := descriptions[0].get_text(" ", strip=True)):
        extra["interests"] = value
    # Only a count adjacent to the profile's Comments heading is a comment total.
    comment_counts = set()
    for heading in section.select('div.section-title'):
        if heading.get_text(" ", strip=True) == "Comments:":
            sibling = heading.find_next_sibling()
            value = sibling.get_text(" ", strip=True) if sibling else None
            if value and re.fullmatch(r"[0-9]+", value):
                comment_counts.add(value)
    if len(comment_counts) == 1:
        extra["comments"] = comment_counts.pop()
    avatars = section.select('.profile-image-wrapper img.profile-image')
    if len(avatars) == 1:
        avatar = avatars[0]
        if raw := _text(avatar.get("src")):
            if url := _media_url(raw):
                media["avatar"] = url
        link = avatar.find_parent('a')
        if link is not None and link in section.descendants and (raw := _text(link.get("href"))):
            if url := _media_url(raw):
                media["avatar_full"] = url
    return Result.taken(extra=extra, media=media)


def friends(response, user):
    try:
        soup, _, _ = _document(response, user)
    except ValueError:
        return {}
    counts = {node.get_text(" ", strip=True) for node in soup.select('li.page.item-count')}
    if len(counts) == 1 and (match := re.fullmatch(r"([0-9]+)\s+items", counts.pop())):
        return {"friends": match[1]}
    return {}
