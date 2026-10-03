"""Public username profiles on the two retained Codeberg/Gitea instances."""
from __future__ import annotations

import json

from .models import Status

HOSTS = {"codeberg": "codeberg.org", "gitea": "gitea.com"}


def catalogue_scope(site) -> bool:
    host = HOSTS.get(site.id)
    if not host or site.id_type != "username" or site.method != "GET":
        return False
    base = f"https://{host}"
    return (site.url == base + "/{username}" and site.url_probe == base + "/api/v1/users/{username}"
            and not site.payload and not site.strip_chars
            and all(key.lower() in {"accept", "accept-language", "user-agent"} for key in site.headers))


def profile_outcome(code: int, text: str, query: str, headers=None) -> tuple[Status, dict, str | None]:
    if code == 429:
        return Status.RATE_LIMITED, {}, "Public-profile API rate limited the request"
    if code in (401, 403, 406, 407, 418, 451) or (headers or {}).get("cf-mitigated", "").lower() == "challenge":
        return Status.BLOCKED, {}, "Public-profile API requires access or challenge resolution"
    if code not in (200, 404):
        return (Status.ERROR if code >= 500 else Status.UNKNOWN), {}, f"Unexpected profile response (HTTP {code})"
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return Status.UNKNOWN, {}, "Profile response is not valid JSON"
    if not isinstance(data, dict):
        return Status.UNKNOWN, {}, "Profile response is not an object"
    if code == 404:
        message = data.get("message")
        # Existing catalogue marker, qualified by HTTP status and no profile.
        missing = isinstance(message, str) and (message == "user redirect does not exist"
                   or message.startswith("user redirect does not exist ["))
        if missing and data.get("id") is None and data.get("login") is None:
            return Status.NOT_FOUND, {}, None
        return Status.UNKNOWN, {}, "Response lacks explicit missing-user evidence"
    if (type(data.get("id")) is not int or data["id"] <= 0 or not isinstance(data.get("login"), str)
            or not data["login"] or data["login"].lower() != query.lower() or data.get("message") or data.get("error")):
        return Status.UNKNOWN, {}, "Response lacks a typed profile matching the requested username"
    fields = {"id": data["id"], "login": data["login"]}
    for key in ("full_name", "email", "created", "location", "website"):
        if isinstance(data.get(key), str) and data[key]:
            fields[key] = data[key]
    return Status.FOUND, fields, None


def native_result(response, query):
    from consensus_osint.vendor.user_scanner.core.result import Result

    status, fields, note = profile_outcome(response.status_code, response.text, query, response.headers)
    if status is Status.FOUND:
        return Result.taken(extra=fields)
    if status is Status.NOT_FOUND:
        return Result.available()
    return Result.error(note)
