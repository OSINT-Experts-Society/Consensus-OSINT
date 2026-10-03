"""Vinted member evidence from structured data or active named member links."""

import json
import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.nextjs import iter_next_app_flight_chunks
from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .provider_contracts import has_service_error


def result(response, user, origin="https://www.vinted.pt"):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    page = BeautifulSoup(response.text, "html.parser")
    for node in page(["style", "template", "noscript"]):
        node.decompose()
    ids = set()

    def record(value):
        if isinstance(value, dict):
            if has_service_error(value):
                return
            login, uid = value.get("login"), value.get("id")
            if isinstance(login, str) and login.casefold() == user.casefold() and type(uid) is int and uid > 0:
                ids.add(str(uid))
            for child in value.values():
                if isinstance(child, (dict, list)):
                    record(child)
        elif isinstance(value, list):
            for child in value:
                record(child)

    for node in page.select("script:not([src])"):
        script = node.get_text()
        if node.get("type") == "application/json" or node.get("id") == "__NEXT_DATA__":
            try:
                record(json.loads(script, object_pairs_hook=_unique_object))
            except (ValueError, RecursionError):
                return Result.error("Invalid or ambiguous Vinted page data")
        for chunk in iter_next_app_flight_chunks(script):
            for line in chunk.splitlines():
                match = re.fullmatch(r"[0-9a-fA-F]+:(.+)", line)
                if match:
                    try:
                        record(json.loads(match[1], object_pairs_hook=_unique_object))
                    except (ValueError, RecursionError):
                        if match[1].lstrip().startswith(("{", "[")):
                            return Result.error("Invalid or ambiguous Vinted streamed data")
    for node in page("script"):
        node.decompose()
    for node in page.select("a[href]"):
        if node.get_text(" ", strip=True).casefold() != user.casefold():
            continue
        try:
            url = urlsplit(urljoin(origin, node["href"]))
        except ValueError:
            continue
        match = re.fullmatch(r"/member/([0-9]+)-(.+?)/?", url.path)
        if (url.scheme == "https" and url.netloc == urlsplit(origin).netloc and not url.query and not url.fragment
                and match and match[2].casefold() == user.casefold() and int(match[1]) > 0):
            ids.add(match[1])
    if len(ids) != 1:
        return Result.error("No unambiguous matching Vinted member; search absence is inconclusive")
    return Result.taken(extra={"id": next(iter(ids)), "username": user})
