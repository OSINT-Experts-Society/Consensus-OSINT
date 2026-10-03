import json
import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.named_user_contracts import _text, _url
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.core.soundcloud_contracts import _Scripts
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate

PLACEHOLDER_AVATAR = "/img/Icon_BentBox"


class _ProfileScripts(_Scripts):
    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        if tag == "script":
            values = dict(attrs)
            eligible = (not self.ignored and len(values) == len(attrs) and "src" not in values
                        and (values.get("type") or "").casefold() == "application/ld+json")
            self.current = [] if eligible else None


def validate_bentbox(user):
    url = "https://bentbox.co/" + quote(user, safe="")
    return generic_validate(url, lambda response: _result(response, user), show_url=url, follow_redirects=False)


def _result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    profiles = []
    try:
        for script in _ProfileScripts(response.text).scripts:
            data = json.loads(script, object_pairs_hook=_unique_object)
            if isinstance(data, dict) and data.get("@type") == "ProfilePage":
                profiles.append(data)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous BentBox structured data")
    if len(profiles) != 1 or has_service_error(profiles[0]):
        return Result.error("No unique BentBox ProfilePage")
    person = profiles[0].get("mainEntity")
    if not isinstance(person, dict) or person.get("@type") != "Person" or has_service_error(person):
        return Result.error("No successful BentBox Person object")
    handle = person.get("alternateName")
    identity = person.get("identifier")
    valid_id = type(identity) is int and identity > 0 or bool(_text(identity))
    # alternateName can echo the requested casing; it is a consistency check,
    # not independent proof of ownership. Require the server profile ID too.
    if not valid_id or not isinstance(handle, str) or not handle or handle.casefold() != user.casefold():
        return Result.error("BentBox profile identity does not match the requested handle")
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    extra = {"username": handle, "profile_id": identity, "scope": "BentBox creator page; not proof of ownership"}
    if name := _text(person.get("name")):
        extra["fullname"] = name
    bios = soup.select('p.fs-lg.mb-0')
    if len(bios) == 1 and (bio := bios[0].get_text(" ", strip=True)):
        extra["bio"] = bio
    counts = set()
    counters = person.get("interactionStatistic")
    if isinstance(counters, list):
        for counter in counters:
            if (isinstance(counter, dict) and counter.get("interactionType") in
                    ("https://schema.org/FollowAction", "http://schema.org/FollowAction")):
                value = counter.get("userInteractionCount")
                if type(value) is int and value >= 0:
                    counts.add(value)
    if len(counts) == 1:
        extra["followers"] = counts.pop()
    reserved = {"username", "profile_id", "scope", "fullname", "name", "bio", "followers", "media"}
    stats = {}
    for node in soup.select('span.stat-value'):
        label = node.find_next_sibling()
        value = node.get_text(" ", strip=True)
        if label is None or label.name != "span" or "stat-label" not in label.get("class", []):
            continue
        key = label.get_text(" ", strip=True).casefold()
        if re.fullmatch(r"[a-z]+", key) and key not in reserved and re.fullmatch(r"[0-9]+", value):
            stats.setdefault(key, []).append(value)
    extra.update({key: values[0] for key, values in stats.items() if len(values) == 1})
    media = {}
    images = soup.select('meta[property="og:image"]')
    if len(images) == 1:
        raw = images[0].get("content")
        if isinstance(raw, str) and "\\" not in raw and PLACEHOLDER_AVATAR not in raw and (avatar := _url(raw)):
            media["avatar"] = avatar
    return Result.taken(extra=extra, media=media)
