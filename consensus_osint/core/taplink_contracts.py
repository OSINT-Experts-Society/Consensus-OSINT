"""Taplink evidence bound to an active, matching profile URL."""

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
    for node in page(["template", "style"]):
        node.decompose()
    accounts = []
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    for node in page.select("script:not([src])"):
        script = node.get_text()
        for match in re.finditer(r"window\.account\s*=\s*", script):
            try:
                account, end = decoder.raw_decode(script[match.end():])
                if not script[match.end() + end:].lstrip().startswith(";"):
                    return Result.error("Invalid account assignment")
                accounts.append(account)
            except (TypeError, ValueError):
                return Result.error("Invalid account JSON")
    if len(accounts) > 1 or any(not isinstance(x, dict) or has_service_error(x) for x in accounts):
        return Result.error("Ambiguous or unsuccessful Taplink account data")
    for node in page("script"):
        node.decompose()
    expected = "https://taplink.cc/" + quote(user, safe="")
    urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
    urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
    if not urls or any(url.rstrip("/").casefold() != expected.casefold() for url in urls):
        return Result.error("No matching Taplink profile URL")
    extra, media = {"username": user}, {}
    account = accounts[0] if accounts else {}
    for key in ("account_id", "profile_id"):
        value = account.get(key)
        if _text(value) or (type(value) is int and value > 0):
            extra[key] = value
    for source, target in (("language_code", "language"), ("tariff_current", "plan")):
        if value := _text(account.get(source)):
            extra[target] = value
    titles = page.select('meta[property="og:title"]')
    if len(titles) == 1:
        title = titles[0].get("content", "")
        if title.endswith(" at Taplink") and (name := title.removesuffix(" at Taplink").strip()):
            if name.casefold() not in ("not found", "page not found", "404", "error"):
                extra["name"] = name
    if "name" not in extra and not {"account_id", "profile_id"}.issubset(extra):
        return Result.error("No coherent profile title or account IDs")
    images = page.select('meta[property="og:image"]')
    if len(images) == 1:
        value = images[0].get("content", "")
        value = "https:" + value if value.startswith("//") else value
        if (url := _url(value)) and not url.endswith("taplink-opengraph.jpg"):
            media["avatar"] = url
    return Result.taken(extra=extra, media=media)
