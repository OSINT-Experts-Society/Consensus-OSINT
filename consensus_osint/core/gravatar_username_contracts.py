"""Legacy Gravatar JSON profile evidence for username lookups."""
import json
from urllib.parse import quote

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
        body = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous Gravatar JSON")
    entries = body.get("entry") if isinstance(body, dict) and not has_service_error(body) else None
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        return Result.error("No unique Gravatar profile")
    entry = entries[0]
    name = entry.get("preferredUsername")
    if has_service_error(entry) or not isinstance(name, str) or name.casefold() != user.casefold():
        return Result.error("Gravatar profile does not match the username")
    if "profileUrl" in entry:
        expected = {f"https://{host}/{quote(name, safe='')}" for host in ("gravatar.com", "en.gravatar.com")}
        url = _url(entry["profileUrl"])
        if not url or url.rstrip("/") not in expected:
            return Result.error("Conflicting Gravatar profile URL")
    extra, media = {"username": name}, {}
    for key, target in (("hash", "gravatar_id"), ("aboutMe", "bio"), ("currentLocation", "location")):
        if value := _text(entry.get(key)):
            extra[target] = value
    full = entry.get("name")
    full = _text(full.get("formatted")) if isinstance(full, dict) else None
    if value := full or _text(entry.get("displayName")):
        extra["fullname"] = value
    if value := _url(entry.get("thumbnailUrl")):
        media["avatar"] = value
    for sources, target, parser in (((('emails', 'value'),), 'emails', _text), ((('accounts', 'url'), ('urls', 'value')), 'links', _url)):
        values = []
        for source, key in sources:
            rows = entry.get(source)
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict) and (value := parser(row.get(key))) and value not in values:
                    values.append(value)
        if values:
            extra[target] = ", ".join(values)
    return Result.taken(extra=extra, media=media)
