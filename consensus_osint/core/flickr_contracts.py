"""Flickr owner-bound embedded models and independent public enrichment."""

import json
import re
from urllib.parse import unquote

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def _mapping(value):
    return value if isinstance(value, dict) else {}


def models(response):
    issue, _ = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return {}
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["style", "template"]):
        node.decompose()
    chunks = []
    for script in page.select("script:not([src])"):
        chunks.extend(re.findall(r"modelExport:\s*(.*?),\s*auth", script.get_text(), re.S))
    if len(chunks) != 1:
        return {}
    try:
        data = json.loads(unquote(chunks[0]), object_pairs_hook=_unique_object)
    except ValueError:
        return {}
    data = _mapping(data)
    main = _mapping(data.get("main"))
    return {} if has_service_error(data) or has_service_error(main) else main


def _records(main, key):
    entries = main.get(key)
    if not isinstance(entries, list):
        return []
    return [entry["data"] for entry in entries if isinstance(entry, dict) and not has_service_error(entry)
            and isinstance(entry.get("data"), dict) and not has_service_error(entry["data"])]


def _bound(main, key, nsid):
    rows = [row for row in _records(main, key) if isinstance(nsid, str) and row.get("id") == nsid]
    return rows[0] if len(rows) == 1 else {}


def result(response, user):
    main = models(response)
    owners = []
    for stream in _records(main, "photostream-models"):
        owner = _mapping(stream.get("owner"))
        if has_service_error(owner):
            continue
        owner = _mapping(owner.get("data")) if "data" in owner else owner
        if not has_service_error(owner) and any(isinstance(owner.get(key), str) and owner[key].casefold() == user.casefold() for key in ("pathAlias", "id")):
            if owner not in owners:
                owners.append(owner)
    if len(owners) != 1:
        return Result.error("No unique matching Flickr photostream owner")
    owner = owners[0]
    nsid = owner.get("id")
    profile = _bound(main, "person-profile-models", nsid)
    contacts = _bound(main, "person-contacts-count-models", nsid)
    extra, media = {"username": user}, {}
    for obj, source, target in ((owner, "username", "display_name"), (owner, "realname", "fullname"), (owner, "id", "user_id"), (owner, "pathAlias", "path_alias"), (profile, "location", "location")):
        if value := _text(obj.get(source)):
            extra[target] = value
    for obj, source, target in ((profile, "photoCount", "photos"), (contacts, "followerCount", "followers"), (contacts, "followingCount", "following")):
        if type(obj.get(source)) is int and obj[source] >= 0:
            extra[target] = obj[source]
    icon = _mapping(owner.get("buddyicon"))
    raw = _mapping(icon.get("data")).get("retina") or icon.get("retina")
    if isinstance(raw, str) and raw.startswith("//"):
        raw = "https:" + raw
    if value := _url(raw):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)


def public_profile(response, nsid):
    profile = _bound(models(response), "person-public-profile-models", nsid)
    return {key: value for key in ("facebook", "instagram", "pinterest", "tumblr", "twitter", "occupation") if (value := _text(profile.get(key)))}
