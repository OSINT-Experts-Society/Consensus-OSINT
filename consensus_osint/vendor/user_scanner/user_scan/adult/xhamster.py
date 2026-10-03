import html
import json
import re
from urllib.parse import quote, unquote, urlsplit

from bs4 import BeautifulSoup, Comment

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.core.soundcloud_contracts import _Scripts
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def _state(document):
    quoted = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
    pattern = (r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted
               + r"|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*"
               + r"|(?P<assignment>(?<![\w$.])(?:initials|window\s*(?:\.\s*initials|\[\s*(?:'initials'|\"initials\")\s*\]))\s*=)")
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    states = []
    for script in _Scripts(document).scripts:
        for match in re.finditer(pattern, script):
            if match["assignment"] is None:
                continue
            start = match.end()
            while start < len(script) and script[start].isspace():
                start += 1
            data, end = decoder.raw_decode(script, start)
            tail = script[end:].lstrip()
            if tail and not tail.startswith(";"):
                raise ValueError("Unsupported xHamster state")
            states.append(data)
    if not states:
        return None
    if len(states) != 1 or not isinstance(states[0], dict) or has_service_error(states[0]):
        raise ValueError("Missing or ambiguous xHamster state")
    return states[0]



def _route(raw, user):
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return False
    try:
        parsed = urlsplit(raw)
        return (parsed.scheme == "https" and parsed.netloc == "xhamster.com" and not parsed.query and not parsed.fragment
                and unquote(parsed.path).rstrip("/").casefold() == ("/users/profiles/" + user).casefold())
    except ValueError:
        return False


def validate_xhamster(user):
    url = "https://xhamster.com/users/profiles/" + quote(user, safe="")
    return generic_validate(url, lambda response: _result(response, user), show_url=url, follow_redirects=False)


def _result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    for node in soup.find_all(string=lambda value: isinstance(value, Comment)):
        node.extract()
    canonicals = soup.select('link[rel~="canonical"]')
    if len(canonicals) > 1 or canonicals and not _route(canonicals[0].get("href"), user):
        return Result.error("Ambiguous or mismatched xHamster canonical URL")
    try:
        state = _state(response.text)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous xHamster profile state")
    model = state.get("userModel") if isinstance(state, dict) else None
    bound_state = isinstance(model, dict) and not has_service_error(model) and _route(model.get("pageURL"), user)
    if model is not None and not bound_state:
        return Result.error("xHamster state identifies another or failed profile")
    titles = soup.select('title')
    title_match = (len(titles) == 1 and titles[0].get_text(" ", strip=True).casefold()
                   == (user + "'s profile | xHamster").casefold())
    if not user or not bound_state and not (canonicals and title_match):
        return Result.error("No matching active xHamster profile evidence")
    extra = {"username": user}
    rows = {}
    reserved = {"username", "about", "profile_views", "subscribers", "days_on_site", "last_seen", "media", "scope"}
    for row in soup.select('div.info-row'):
        labels, values = row.select('div.label'), row.select('div.value')
        if len(labels) != 1 or len(values) != 1:
            continue
        label = labels[0].get_text(" ", strip=True).rstrip(":").strip().casefold()
        key = "location" if label == "from" else label.replace(" ", "_")
        value = html.unescape(values[0].get_text(" ", strip=True))
        if label != "interests and fetishes" and key and key not in reserved and not key.startswith("_") and value:
            rows.setdefault(key, []).append(value)
    extra.update({key: values[0] for key, values in rows.items() if len(values) == 1})
    stats = {}
    for node in soup.select('b'):
        value, label = node.get_text(" ", strip=True), node.next_sibling
        if not isinstance(label, str):
            continue
        for text, key in (("profile views", "profile_views"), ("subscribers", "subscribers")):
            if label.strip().casefold() == text and re.fullmatch(r"[0-9]+(?:[.,][0-9]+)*[KMkm]?", value):
                stats.setdefault(key, []).append(value)
        if label.strip().casefold() == "on xhamster" and re.fullmatch(r"[0-9,]+ days", value):
            stats.setdefault("days_on_site", []).append(value)
    extra.update({key: values[0] for key, values in stats.items() if len(values) == 1})
    seen = []
    for node in soup.select('div'):
        text = " ".join(str(value).strip() for value in node.find_all(string=True, recursive=False)).strip()
        if text.casefold().startswith("last seen ") and text[10:].strip():
            seen.append(text[10:].strip())
    if len(seen) == 1:
        extra["last_seen"] = seen[0]
    about = state.get("profileEditableAboutMe") if bound_state else None
    if isinstance(about, dict) and not has_service_error(about) and isinstance(about.get("about"), str):
        fragment = BeautifulSoup(about["about"], "html.parser")
        for node in fragment.find_all(["script", "style", "template", "noscript"]):
            node.decompose()
        if text := fragment.get_text(" ", strip=True):
            extra["about"] = text
    return Result.taken(extra=extra)
