import json
import re
from datetime import date
from urllib.parse import quote, unquote, urlsplit

from bs4 import BeautifulSoup, Comment

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_faproulette(user):
    url = "https://faproulette.co/@" + quote(user, safe="")
    return generic_validate(url, lambda response: _result(response, user), show_url=url, follow_redirects=False)


def _route(raw, user):
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return False
    try:
        parsed = urlsplit(raw)
        return (parsed.scheme == "https" and parsed.netloc == "faproulette.co" and not parsed.query and not parsed.fragment
                and unquote(parsed.path).rstrip("/").casefold() == ("/@" + user).casefold())
    except ValueError:
        return False


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
    titles = soup.select('meta[property="og:title"]')
    if not user or len(canonicals) != 1 or not _route(canonicals[0].get("href"), user) or len(titles) != 1:
        return Result.error("No unique matching Faproulette profile URL and title")
    title = titles[0].get("content")
    name = re.fullmatch(r"(.+)'s Profile - Fap Roulette", title, re.IGNORECASE) if isinstance(title, str) else None
    if name is None or not name[1].strip():
        return Result.error("No Faproulette profile title")
    extra = {"username": user, "name": name[1].strip()}
    joined = []
    for label in soup.select('span.type'):
        if label.get_text(" ", strip=True).casefold() != "joined":
            continue
        # Only the adjacent value belongs to this label, not a later page date.
        value = label.next_sibling
        while isinstance(value, str) and not value.strip():
            value = value.next_sibling
        text = value.strip() if isinstance(value, str) else value.get_text(" ", strip=True) if value else ""
        try:
            if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
                joined.append(date.fromisoformat(text).isoformat())
        except ValueError:
            pass
    if len(joined) == 1:
        extra["joined"] = joined[0]
    totals = []
    # Retain a total only in a complete JSON attribute identifying this handle.
    # Arbitrary script fragments and counts belonging to other profiles are not evidence.
    for node in soup.find_all(True):
        for value in node.attrs.values():
            if not isinstance(value, str) or not value.lstrip().startswith("{") or "roulettes_total" not in value:
                continue
            try:
                data = json.loads(value, object_pairs_hook=_unique_object)
            except (TypeError, ValueError):
                continue
            if (isinstance(data, dict) and not has_service_error(data) and isinstance(data.get("username"), str)
                    and data["username"].casefold() == user.casefold()
                    and type(data.get("roulettes_total")) is int and data["roulettes_total"] >= 0):
                totals.append(data["roulettes_total"])
    if len(totals) == 1:
        extra["roulettes"] = totals[0]
    return Result.taken(extra=extra)
