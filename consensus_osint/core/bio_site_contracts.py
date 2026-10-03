"""Active Bio Site initial state bound to the requested handle."""

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
    states = []
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    for script in page.select("script:not([src])"):
        text = script.get_text()
        for match in re.finditer(r"window\.initial_state\s*=\s*", text):
            try:
                state, end = decoder.raw_decode(text[match.end():])
            except ValueError:
                return Result.error("Invalid embedded profile state")
            if not re.match(r"\s*;\s*window\.additional", text[match.end() + end:]):
                return Result.error("Unexpected profile state boundary")
            states.append(state)
    if len(states) != 1 or not isinstance(states[0], dict) or has_service_error(states[0]):
        return Result.error("No unique coherent Bio Site state")
    state = states[0]
    metadata = state.get("metadata")
    if (not isinstance(metadata, dict) or has_service_error(metadata)
            or not isinstance(metadata.get("handle"), str) or metadata["handle"].casefold() != user.casefold()):
        return Result.error("State does not identify the requested Bio Site handle")
    extra, media = {"username": metadata["handle"]}, {}
    header = state.get("header")
    if isinstance(header, dict) and not has_service_error(header):
        for key in ("name", "bio"):
            if value := _text(header.get(key)):
                extra[key] = value
        for key in ("profilePhoto", "profile_photo"):
            if value := _url(header.get(key)):
                media["avatar"] = value
                break
    return Result.taken(extra=extra, media=media)
