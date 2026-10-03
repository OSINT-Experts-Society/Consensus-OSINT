"""Clubhouse active Next.js user identity and typed profile metadata."""

import json

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
    scripts = page.select('script#__NEXT_DATA__:not([src])')
    if len(scripts) != 1:
        return Result.error("No unique active Clubhouse page data")
    try:
        data = json.loads(scripts[0].get_text(), object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous Clubhouse JSON")
    current = data
    route = None
    for key in ("props", "pageProps", "routeProps", "user"):
        if (not isinstance(current, dict) or has_service_error(current)
                or current.get("notFound") is True or current.get("__N_REDIRECT")):
            return Result.error("No successful Clubhouse profile data")
        route = current
        current = current.get(key)
    profile = current
    if (not isinstance(profile, dict) or has_service_error(profile)
            or not isinstance(profile.get("username"), str) or profile["username"].casefold() != user.casefold()):
        return Result.error("No matching Clubhouse username")
    extra, media = {"username": profile["username"]}, {}
    for source, target in (("full_name", "fullname"), ("bio", "bio"), ("twitter_username", "twitter"), ("instagram_username", "instagram")):
        if value := _text(profile.get(source)):
            extra[target] = value
    for source, target in (("num_followers", "followers"), ("num_following", "following"), ("friend_count", "friends")):
        if type(route.get(source)) is int and route[source] >= 0:
            extra[target] = route[source]
    if value := _url(profile.get("photo_url")):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
