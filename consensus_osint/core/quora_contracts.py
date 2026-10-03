"""Named Quora profile evidence with independently typed enrichment."""

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


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _extra(profile):
    extra = {}
    for key, field in (("uid", "uid"), ("followers", "followerCount"), ("following", "followingCount"), ("answers", "numPublicAnswers"), ("questions", "numProfileQuestions"), ("posts", "postsCount"), ("content_views", "allTimePublicContentViews"), ("monthly_content_views", "lastMonthPublicContentViews")):
        value = profile.get(field)
        if type(value) is int and value >= 0:
            extra[key] = value
    if type(profile.get("isVerified")) is bool:
        extra["verified"] = profile["isVerified"]
    names = _list(profile.get("names"))
    name = _mapping(names[0]) if names else {}
    for source, target in (("givenName", "first_name"), ("familyName", "last_name")):
        if value := _text(name.get(source)):
            extra[target] = value
    created = profile.get("creationTime")
    if type(created) in (int, float) and 0 <= created <= 253402300799000000:
        try:
            extra["joined"] = datetime.fromtimestamp(created / 1_000_000, timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            pass
    if value := _text(_mapping(profile.get("profileCredential")).get("experience")):
        extra["credential"] = value
    try:
        document = json.loads(_mapping(profile.get("descriptionQtextDocument")).get("legacyJson", ""), object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        document = {}
    sections = _list(_mapping(document).get("sections"))
    paragraphs = []
    for section in sections:
        spans = _list(_mapping(section).get("spans"))
        text = "".join(value for span in spans if isinstance(value := _mapping(span).get("text"), str))
        if text:
            paragraphs.append(text)
    if paragraphs:
        extra["bio"] = "\n".join(paragraphs)
    for key, field, relation, fallback in (("work", "workCredentials", "company", "companyName"), ("schools", "schoolCredentials", "school", "schoolName"), ("location", "locationCredentials", "location", "locationName")):
        values = []
        for raw in _list(profile.get(field)):
            item = _mapping(raw)
            if value := _text(_mapping(item.get(relation)).get("name")) or _text(item.get(fallback)):
                values.append(value)
        if values:
            extra[key] = list(dict.fromkeys(values))
    topics = [_text(_mapping(_mapping(edge).get("node")).get("name")) for edge in _list(_mapping(profile.get("expertiseTopicsConnection")).get("edges"))]
    publishers = [_text(_mapping(item).get("publisherName")) for item in _list(profile.get("publishers"))]
    years = [str(value) for value in _list(profile.get("topWriterYears")) if type(value) is int and 1900 <= value <= 9999]
    for key, values in (("topics", topics), ("publishers", publishers), ("top_writer_years", years)):
        values = list(dict.fromkeys(value for value in values if value))
        if values:
            extra[key] = values
    return extra


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["style", "template"]):
        node.decompose()
    scripts = [node.get_text() for node in page.select("script:not([src])")]
    for node in page("script"):
        node.decompose()
    expected = "https://www.quora.com/profile/" + quote(user, safe="")
    urls = [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    urls += [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    types = [node.get("content", "") for node in page.select('meta[property="og:type"]')]
    if not urls or any(value.rstrip("/").casefold() != expected.casefold() for value in urls) or types != ["profile"]:
        return Result.error("No matching Quora profile metadata")
    profiles = []
    for script in scripts:
        for encoded in re.findall(r'\.push\(("(?:[^"\\]|\\.)*")\);', script):
            try:
                payload = json.loads(json.loads(encoded), object_pairs_hook=_unique_object)
            except (TypeError, ValueError):
                continue
            if not isinstance(payload, dict) or has_service_error(payload):
                continue
            data = _mapping(payload.get("data"))
            profile = _mapping(data.get("user"))
            if has_service_error(data) or has_service_error(profile):
                continue
            profile_url = profile.get("profileUrl")
            if isinstance(profile_url, str) and profile_url.casefold() in (("/profile/" + user).casefold(), ("/profile/" + quote(user, safe="")).casefold()):
                if profile not in profiles:
                    profiles.append(profile)
    if len(profiles) != 1:
        return Result.error("No unique matching embedded Quora profile")
    profile = profiles[0]
    extra, media = {"username": user, **_extra(profile)}, {}
    avatar = _url(profile.get("profileImageUrl"))
    if avatar and not any(marker in avatar for marker in ("share_default_image", "profile_default")):
        media["avatar"] = avatar
    return Result.taken(extra=extra, media=media)
