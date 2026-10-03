"""Active Direct.me profile identity with bound optional structured metadata."""

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
    records = []
    for node in page.select('script[type="application/ld+json"]:not([src])'):
        try:
            root = json.loads(node.get_text(), object_pairs_hook=_unique_object)
        except ValueError:
            continue
        graph = root.get("@graph") if isinstance(root, dict) and not has_service_error(root) else None
        if isinstance(graph, list):
            for record in graph:
                if not isinstance(record, dict) or record.get("@type") != "ProfilePage" or has_service_error(record):
                    continue
                person = record.get("mainEntity")
                if (isinstance(person, dict) and person.get("@type") == "Person" and not has_service_error(person)
                        and isinstance(person.get("identifier"), str) and person["identifier"].casefold() == user.casefold()):
                    records.append((record, person))
    for node in page("script"):
        node.decompose()
    expected = "https://direct.me/" + quote(user, safe="")
    urls = [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    urls += [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    handles = [node.get("content", "") for node in page.select('meta[property="profile:username"]')]
    legacy = [node for node in page.select("a.avatarBlockSub.textPrimary") if node.get_text(strip=True).casefold() == ("direct.me/" + user).casefold() and node.get("href", "").rstrip("/").casefold() == expected.casefold()]
    if (not urls or any(value.rstrip("/").casefold() != expected.casefold() for value in urls)
            or (handles and any(value.casefold() != user.casefold() for value in handles)) or not (handles or len(legacy) == 1)):
        return Result.error("No matching active Direct.me profile")
    extra, media = {"username": user}, {}
    def meta(key):
        nodes = page.select(f'meta[name="{key}"], meta[property="{key}"]')
        return _text(nodes[0].get("content")) if len(nodes) == 1 else None
    if value := meta("author") or meta("og:title"):
        extra["name"] = value.removesuffix(" on Direct.me")
    if value := _url(meta("og:image")):
        media["avatar"] = value
    bios = page.select(".themePageProfileHeader__bio, .bio")
    if len(bios) == 1 and (value := bios[0].get_text(" ", strip=True)):
        extra["bio"] = value
    links = []
    for anchor in page.select("a[href]"):
        if "socialIcon-item" in anchor.get("class", []) or anchor.select_one('[class^="profileSocialIcon"]'):
            if value := _url(anchor.get("href")):
                links.append(value)
    if len(records) == 1:
        record, person = records[0]
        if all(not obj.get("url") or obj["url"] == expected for obj in (record, person)):
            for key, target in (("dateCreated", "created_at"), ("dateModified", "updated_at")):
                if value := _text(record.get(key)):
                    extra[target] = value
            if "bio" not in extra and (value := _text(person.get("description"))):
                if not ("Find their " in value and value.endswith(" on Direct.me.")):
                    extra["bio"] = value
            if isinstance(person.get("sameAs"), list):
                links.extend(value for raw in person["sameAs"] if (value := _url(raw)))
    if links:
        extra["social_links"] = list(dict.fromkeys(links))
    verified = page.select('[aria-label^="Verified"]')
    if len(verified) == 1:
        extra["verified"] = True
    return Result.taken(extra=extra, media=media)
