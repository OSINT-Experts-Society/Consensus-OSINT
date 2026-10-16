"""CodePen page evidence and optional query-bound profile enrichment."""

import html
import json
import re

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue, valid_token
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error

PROFILE_QUERY = """
query ProfileOwner($ownerUsername: String!, $ownerType: OwnerEnum!) {
  ownerByUsername(ownerUsername: $ownerUsername, ownerType: $ownerType) {
    id
    username
    title
    avatar512
    pro
    urls
    location
    bio
    verified
    counts {
      id
      followers
      following
      pens
      posts
      collections
    }
  }
}
"""


def profile_request(url, **kwargs):
    from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request

    kwargs["allow_redirects"] = kwargs.pop("follow_redirects", False)
    return impersonate_request(url, **kwargs)


def process(response, user, url, owner_type, request):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["script", "template", "style"]):
        node.decompose()
    urls = [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    urls += [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    if not urls or any(value.rstrip("/").casefold() != url.casefold() for value in urls):
        return Result.error("Profile URL does not match requested owner")
    names = [node.get("content", "") for node in page.select('meta[property="profile:username"]')]
    title = page.title.get_text(" ", strip=True) if page.title else ""
    if names and any(name.casefold() != user.casefold() for name in names):
        return Result.error("Conflicting profile owner")
    named = bool(re.search(r"(?<![\w.-])" + re.escape(user) + r"(?![\w.-])", title, re.I))
    if not names and not (named and "codepen" in title.casefold()):
        return Result.error("No named CodePen profile evidence")
    extra, media = {}, {}
    tokens = [node.get("content") for node in page.select('meta[name="csrf-token"]')]
    if len(tokens) != 1 or not valid_token(tokens[0]):
        return Result.taken(extra=extra, media=media)
    try:
        api = request("https://codepen.io/graphql", method="POST", follow_redirects=False,
                      headers={"referer": url, "x-csrf-token": tokens[0]},
                      json={"query": PROFILE_QUERY, "variables": {"ownerType": owner_type, "ownerUsername": user}})
        issue, _ = http_issue(api.status_code, api.headers, api.text)
        if issue is not None:
            return Result.taken()
        data = json.loads(api.text, object_pairs_hook=_unique_object)
        envelope = data.get("data") if isinstance(data, dict) else None
        record = envelope.get("ownerByUsername") if isinstance(envelope, dict) else None
        if (not isinstance(record, dict) or has_service_error(data) or has_service_error(envelope)
                or has_service_error(record) or not isinstance(record.get("username"), str)
                or record["username"].casefold() != user.casefold() or not _text(record.get("id"))):
            return Result.taken()
        extra["hashid"] = record["id"]
        counts = record.get("counts")
        if isinstance(counts, dict) and not has_service_error(counts):
            for key in ("id", "followers", "following", "pens", "posts", "collections"):
                if type(counts.get(key)) is int and counts[key] >= 0:
                    extra[key] = counts[key]
        for key in ("pro", "verified"):
            if type(record.get(key)) is bool:
                extra[key] = record[key]
        if isinstance(record.get("urls"), list):
            links = list(dict.fromkeys(value for raw in record["urls"] if (value := _url(raw))))
            if links:
                extra["links"] = links
        for source, target in (("location", "location"), ("title", "fullname"), ("bio", "bio")):
            if value := _text(record.get(source)):
                extra[target] = html.unescape(value)
        if value := _url(record.get("avatar512")):
            media["avatar"] = value
    except Exception:
        pass  # Optional enrichment must not erase the bound page result.
    return Result.taken(extra=extra, media=media)
