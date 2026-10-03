"""Guard npm scope responses and optional profile metadata."""

import base64
import json
from urllib.parse import quote

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 404))
    if issue is not None:
        return Result.error(reason)
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    if not isinstance(data, dict) or has_service_error(data):
        return Result.error("No coherent npm scope response")
    if response.status_code == 404:
        if data.get("message") == "Scope not found" and "scope" not in data:
            return Result.available()
        return Result.error("No unambiguous missing-scope response")
    scope = data.get("scope")
    parent = scope.get("parent") if isinstance(scope, dict) else None
    if (not isinstance(parent, dict) or has_service_error(scope) or has_service_error(parent)
            or parent.get("name") != user):
        return Result.error("No matching npm scope")
    extra, media = {"username": user, "scope": "npm user or organisation scope; not ownership proof"}, {}
    resource = parent.get("resource")
    if isinstance(resource, dict) and not has_service_error(resource):
        if value := _text(resource.get("fullname")):
            extra["fullname"] = value
        if value := _text(resource.get("github")):
            extra["github"] = "https://github.com/" + quote(value, safe="")
    for source, target in (("type", "type"), ("created", "created")):
        if value := _text(scope.get(source)):
            extra[target] = value
    identifier = scope.get("id")
    if _text(identifier) or (type(identifier) is int and identifier > 0):
        extra["id"] = identifier
    if value := _text(parent.get("description")):
        extra["description"] = value
    packages = data.get("packages")
    if isinstance(packages, dict) and type(packages.get("total")) is int and packages["total"] >= 0:
        extra["packages"] = packages["total"]
    avatars = parent.get("avatars")
    path = avatars.get("large") if isinstance(avatars, dict) else None
    if isinstance(path, str) and len(path) <= 8192 and path.startswith("/npm-avatar/"):
        try:
            payload = path.rsplit("/", 1)[-1].split(".")[1]
            decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)), object_pairs_hook=_unique_object)
            value = _url(decoded.get("avatarURL")) if isinstance(decoded, dict) else None
        except (ValueError, TypeError, IndexError, UnicodeError):
            value = None
        if value:
            media["avatar"] = value
        elif _url("https://www.npmjs.com" + path):
            media["avatar"] = "https://www.npmjs.com" + path
    return Result.taken(extra=extra, media=media)
