"""Query-bound Magnific author data with isolated optional metadata."""

import json
import re

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
    scripts = page.select("script#__NEXT_DATA__")
    if len(scripts) != 1 or scripts[0].has_attr("src"):
        return Result.error("No unique embedded author response")
    try:
        data = json.loads(scripts[0].get_text(), object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data) or data.get("page") != "/author/[authorSlug]":
        return Result.error("No coherent author page data")
    props = data.get("props")
    page_props = props.get("pageProps") if isinstance(props, dict) else None
    author = page_props.get("author") if isinstance(page_props, dict) else None
    if (not isinstance(author, dict) or has_service_error(props) or has_service_error(page_props)
            or has_service_error(author) or not isinstance(author.get("slug"), str)
            or author["slug"].casefold() != user.casefold()):
        return Result.error("Author does not match the requested slug")
    author_id = author.get("id")
    if not (_text(author_id) or (type(author_id) is int and author_id > 0)):
        return Result.error("No typed author ID")
    extra, media = {"author_id": author_id, "slug": author["slug"]}, {}
    if value := _text(author.get("name")):
        extra["name"] = value
    if type(author.get("followers")) is int and author["followers"] >= 0:
        extra["followers"] = author["followers"]
    links = author.get("links")
    if isinstance(links, dict):
        for key, raw in links.items():
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,50}", key) and (value := _url(raw)):
                extra["link_" + key] = value
    totals = author.get("totals")
    if isinstance(totals, dict):
        for name, values in totals.items():
            if isinstance(values, dict) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,50}", name):
                prefix = "" if name == "assets" else f"{name}_"
                for source, target in (("items", "assets"), ("downloads", "downloads")):
                    if type(values.get(source)) is int and values[source] >= 0:
                        extra[prefix + target] = values[source]
    if value := _url(author.get("avatar")):
        media["avatar"] = value
    return Result.taken(extra=extra, media=media)
