"""BDSMLR blog identity and optional public metadata."""
import json

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous BDSMLR JSON")
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No successful BDSMLR response")
    blog = data.get("blog")
    if (not isinstance(blog, dict) or has_service_error(blog) or not _text(blog.get("name"))
            or blog["name"].casefold() != user.casefold()):
        return Result.error("No matching BDSMLR blog; renamed aliases are not verified")
    extra = {"username": blog["name"], "scope": "BDSMLR blog; not proof of account ownership"}
    for key, target in (("id", "blog_id"), ("ownerUserId", "owner_user_id")):
        value = blog.get(key)
        if (type(value) is int and value > 0) or _text(value):
            extra[target] = value
    if title := _text(blog.get("title")):
        extra["fullname"] = title
    if (bio := _text(blog.get("description"))) and bio.casefold() != "no description":
        extra["bio"] = bio
    for key, target in (("postsCount", "posts"), ("followersCount", "followers")):
        if type(blog.get(key)) is int and blog[key] >= 0:
            extra[target] = blog[key]
    personals = blog.get("personals")
    labels = personals.get("labels") if isinstance(personals, dict) else None
    if isinstance(labels, list):
        valid = sorted({value for item in labels if (value := _text(item))})
        if valid:
            extra["personals"] = ", ".join(valid)
    media = {}
    for key, target in (("avatarUrl", "avatar"), ("coverUrl", "cover")):
        if value := _url(blog.get(key)):
            media[target] = value
    return Result.taken(extra=extra, media=media)
