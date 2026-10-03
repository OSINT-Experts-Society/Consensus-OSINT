"""iFunny active profile evidence bound to the requested URL."""
import json
import re
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
    for node in page(["style", "template", "noscript"]):
        node.decompose()
    expected = "https://ifunny.co/user/" + quote(user, safe="")
    urls = [n.get("href", "") for n in page.select('link[rel~="canonical"]')]
    urls += [n.get("content", "") for n in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No matching iFunny profile URL")
    states = []
    for node in page.select("script:not([src])"):
        raw = node.get_text()
        if "window.__INITIAL_STATE__" not in raw:
            continue
        match = re.fullmatch(r"\s*window\.__INITIAL_STATE__\s*=\s*(\{.*\})\s*;?\s*", raw, re.S)
        if not match:
            return Result.error("Unsupported iFunny profile state script")
        try:
            state = json.loads(match[1], object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return Result.error("Invalid or ambiguous iFunny state")
        if not isinstance(state, dict) or has_service_error(state):
            return Result.error("No successful iFunny state")
        profiles = [state[k] for k in ("user", "profile") if k in state and state[k] is not None]
        if len(profiles) != 1 or not isinstance(profiles[0], dict) or has_service_error(profiles[0]):
            return Result.error("No unique iFunny state profile")
        states.append(profiles[0])
    if len(states) > 1:
        return Result.error("Ambiguous iFunny profile state")
    extra, media = {"username": user}, {}
    if states:
        profile = states[0]
        name = _text(profile.get("nick"))
        if not name or name.casefold() != user.casefold():
            return Result.error("iFunny profile nickname does not match")
        extra["name"] = name
        for key in ("subscribers_count", "num_subscribers"):
            if type(profile.get(key)) is int and profile[key] >= 0:
                extra["subscribers"] = profile[key]
                break
        for key in ("photo_url", "avatar_url"):
            if value := _url(profile.get(key)):
                media["avatar"] = value
                break
    else:
        titles = page.select('meta[property="og:title"]')
        name = titles[0].get("content", "") if len(titles) == 1 else ""
        names = [name[:-len(suffix)].strip() for suffix in (" on iFunny", " | iFunny") if name.endswith(suffix)]
        if len(names) != 1 or names[0].casefold() != user.casefold():
            return Result.error("No matching iFunny profile title")
        extra["name"] = names[0]
    images = page.select('meta[property="og:image"]')
    if not media and len(images) == 1 and (value := _url(images[0].get("content"))) and "ifunny_logo" not in value.casefold():
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
