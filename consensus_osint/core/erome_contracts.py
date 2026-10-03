"""Erome profile title/heading identity and unambiguous optional metadata."""
import re

from bs4 import BeautifulSoup, NavigableString

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    titles, headings = soup.select('title'), soup.select('h1')
    if len(titles) != 1 or len(headings) != 1:
        return Result.error("No unique Erome profile title and heading")
    title = titles[0].get_text(" ", strip=True)
    name = headings[0].get_text(" ", strip=True)
    if not user or title.casefold() != (user + " - Profile page - EroMe").casefold() or name.casefold() != user.casefold():
        return Result.error("Erome profile title and heading do not match the requested handle")
    extra = {"username": name, "name": name}
    identities = [node.get("data-var1") for node in soup.select('[data-var1]')]
    if (identities and all(isinstance(value, str) and re.fullmatch(r"[0-9]+", value) for value in identities)
            and len(set(identities)) == 1):
        extra["user_id"] = identities[0]
    stats = {}
    for icon in soup.select('svg'):
        value = icon.next_sibling
        if not isinstance(value, NavigableString) or not re.fullmatch(r"[0-9]+(?:[.,][0-9]+)*[KMkm]?", value.strip()):
            continue
        label = value.next_sibling
        if label is None or getattr(label, "name", None) != "span":
            continue
        key = label.get_text(" ", strip=True).casefold()
        if key in ("albums", "views", "followers", "following"):
            stats.setdefault(key, []).append(value.strip())
    extra.update({key: values[0] for key, values in stats.items() if len(values) == 1})
    badges = [node.get("title") for node in soup.select('div.badge[title]')]
    ages = [value.strip() for value in badges if isinstance(value, str) and "year(s)" in value.casefold()]
    if len(ages) == 1:
        extra["seniority"] = ages[0]
    return Result.taken(extra=extra)
