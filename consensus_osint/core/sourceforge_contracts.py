"""SourceForge API identity and separately bound optional page details."""

import json
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def profile(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return None, reason
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (ValueError, TypeError):
        data = None
    if (not isinstance(data, dict) or has_service_error(data)
            or not isinstance(data.get("username"), str) or data["username"].casefold() != user.casefold()):
        return None, "No matching SourceForge user profile"
    return data, None


def fields(data):
    extra = {"username": data["username"]}
    for key in ("name", "joined", "sex"):
        if (value := _text(data.get(key))) and not (key == "sex" and value == "Unknown"):
            extra[key] = value
    localization = data.get("localization")
    if isinstance(localization, dict):
        parts = [value for key in ("city", "country") if (value := _text(localization.get(key)))]
        if parts:
            extra["location"] = ", ".join(parts)
    for source, target, parser in (("webpages", "webpages", _url), ("telnumbers", "phone_numbers", _text)):
        if isinstance(data.get(source), list):
            values = [value for raw in data[source] if (value := parser(raw))]
            if values:
                extra[target] = ", ".join(values)
    socials, skills, slots = [], [], []
    for entry in _rows(data.get("socialnetworks")):
        if (url := _url(entry.get("accounturl"))) and (name := _text(entry.get("socialnetwork"))):
            socials.append(f"{name}: {url}")
    for entry in _rows(data.get("skills")):
        skill = entry.get("skill")
        if isinstance(skill, dict):
            name = next((v for key in ("fullname", "fullpath", "shortname") if (v := _text(skill.get(key)))), None)
            level = entry.get("level")
            if name:
                valid_level = _text(level) or (str(level) if type(level) is int and level >= 0 else None)
                skills.append(f"{name} ({valid_level})" if valid_level else name)
    for entry in _rows(data.get("availability")):
        values = [_text(entry.get(key)) for key in ("week_day", "start_time", "end_time")]
        if all(values):
            slots.append(f"{values[0]} {values[1]}-{values[2]}")
    for key, values in (("social_networks", socials), ("skills", skills), ("availability", slots)):
        if values:
            extra[key] = "; ".join(values)
    projects = data.get("projects")
    if isinstance(projects, list) and all(isinstance(item, dict) for item in projects):
        extra["projects"] = len(projects)
        names = [name for item in projects[:20] if (name := _text(item.get("name")))]
        if len(projects) > 20:
            names.append(f"(+{len(projects) - 20} more)")
        if names:
            extra["project_names"] = ", ".join(names)
    return extra


def _rows(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def page_fields(response, url):
    issue, _ = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return {}, {}
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "style", "template"]):
        node.decompose()
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(value.rstrip("/").casefold() != url.rstrip("/").casefold() for value in urls):
        return {}, {}
    headers = page.select(".overview")
    if len(headers) != 1:
        return {}, {}
    header = headers[0]
    extra, media = {}, {}
    headlines = header.select("h2.as-h3.summary")
    if len(headlines) == 1 and (value := headlines[0].get_text(" ", strip=True)):
        extra["headline"] = value
    activities = header.select("time[datetime]")
    if activities and (value := _text(activities[0].get("datetime"))):
        extra["last_activity"] = value
    images = [node.get("src", "") for node in header.select("img[src]") if "user_icon" in node.get("src", "")]
    if len(images) == 1 and (value := _url(urljoin(url, images[0]))):
        media["avatar"] = value
    return extra, media
