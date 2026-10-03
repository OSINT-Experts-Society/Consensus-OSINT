"""Identity-bound public API contracts for imported community site definitions."""

from __future__ import annotations

import json
from urllib.parse import unquote, urlsplit

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error

CONTRACTS = frozenset({"discourse", "mediawiki", "lemmy", "mastodon", "gitea", "gitlab"})


def valid_query(contract, query):
    if not query or any(ord(c) < 32 or ord(c) == 127 for c in query):
        return False
    if contract == "mediawiki":
        return not any(c in query for c in "|#[]{}<>")
    return not any(c in query for c in "/\\?#@")


def _id(value):
    return type(value) is int and value > 0


def _matches(value, query):
    return isinstance(value, str) and value.casefold() == query.casefold()


def _profile_url(value, expected):
    if not isinstance(value, str) or "\\" in value or any(ord(c) <= 32 for c in value):
        return False
    try:
        a, b = urlsplit(value), urlsplit(expected)
        return (
            a.scheme == b.scheme == "https"
            and a.hostname == b.hostname
            and not a.username
            and not a.password
            and a.port in (None, 443)
            and not a.query
            and not a.fragment
            and unquote(a.path).rstrip("/").casefold() == unquote(b.path).rstrip("/").casefold()
        )
    except ValueError:
        return False


def outcome(contract, code, text, query, headers, profile_url):
    unknown = (Status.UNKNOWN, {}, "No unambiguous API evidence for the requested account")
    if contract not in CONTRACTS or not valid_query(contract, query):
        return Status.SKIPPED, {}, "A single valid community username is required"
    issue, reason = http_issue(code, headers, text, accepted=(200, 404))
    if issue is not None:
        return issue, {}, reason
    try:
        root = json.loads(text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return unknown

    if contract == "discourse":
        from .discourse_contracts import decoded_profile_outcome

        status, user, reason = decoded_profile_outcome(code, root, query, headers)
        if status is not Status.FOUND:
            return status, {}, reason
        if not _id(user.get("id")) or has_service_error(user):
            return unknown
        fields = {
            k: user[k]
            for k in ("username", "id", "name", "title", "location", "created_at", "bio_raw")
            if isinstance(user.get(k), (str, int)) and not isinstance(user.get(k), bool)
        }
        fields["scope"] = "Public forum profile; account ownership is unverified"
        return Status.FOUND, fields, None

    if contract == "mediawiki":
        if code != 200 or not isinstance(root, dict) or has_service_error(root):
            return unknown
        data = root.get("query")
        users = data.get("users") if isinstance(data, dict) and not has_service_error(data) else None
        if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
            return unknown
        user = users[0]

        # MediaWiki normalizes underscores and the first character, not the whole name.
        def name(value):
            if not isinstance(value, str):
                return None
            value = value.replace("_", " ").strip()
            return value[:1].upper() + value[1:]

        if name(user.get("name")) != name(query) or "invalid" in user or has_service_error(user):
            return unknown
        if user.get("missing") is True and "userid" not in user:
            return Status.NOT_FOUND, {}, None
        if "missing" in user or not _id(user.get("userid")):
            return unknown
        fields = {
            "username": user["name"],
            "user_id": user["userid"],
            "scope": "Wiki account; a user page is not required",
        }
        for key in ("editcount", "registration", "groups"):
            value = user.get(key)
            if (
                key == "editcount"
                and type(value) is int
                and value >= 0
                or key == "registration"
                and isinstance(value, str)
                or key == "groups"
                and isinstance(value, list)
                and all(isinstance(v, str) for v in value)
            ):
                fields[key] = value
        return Status.FOUND, fields, None

    if contract == "gitlab":
        if code != 200 or not isinstance(root, list):
            return unknown
        if not root:
            return Status.NOT_FOUND, {}, None
        if len(root) != 1 or not isinstance(root[0], dict):
            return unknown
        user = root[0]
        if (
            has_service_error(user)
            or not _id(user.get("id"))
            or not _matches(user.get("username"), query)
            or not _profile_url(user.get("web_url"), profile_url)
        ):
            return unknown
    else:
        if not isinstance(root, dict):
            return unknown
        if code == 404:
            if contract == "mastodon" and root == {"error": "Record not found"}:
                return Status.NOT_FOUND, {}, None
            if contract == "lemmy" and root == {"error": "couldnt_find_person"}:
                return Status.NOT_FOUND, {}, None
            if contract == "gitea":
                from .forge_profiles import profile_outcome

                status, _, note = profile_outcome(code, text, query, headers)
                return status, {}, note
            return unknown
        if has_service_error(root):
            return unknown
        if contract == "lemmy":
            view = root.get("person_view")
            user = view.get("person") if isinstance(view, dict) and not has_service_error(view) else None
            if (
                not isinstance(user, dict)
                or has_service_error(user)
                or not _id(user.get("id"))
                or not _matches(user.get("name"), query)
                or user.get("local") is not True
                or user.get("deleted") is True
                or not _profile_url(user.get("actor_id"), profile_url)
            ):
                return unknown
        elif contract == "mastodon":
            user = root
            if (
                not isinstance(user.get("id"), str)
                or not 1 <= len(user["id"]) <= 32
                or not user["id"].isascii()
                or not user["id"].isdigit()
                or int(user["id"]) <= 0
                or not _matches(user.get("username"), query)
                or not _matches(user.get("acct"), query)
                or not _profile_url(user.get("url"), profile_url)
            ):
                return unknown
        else:
            from .forge_profiles import profile_outcome

            status, fields, note = profile_outcome(code, text, query, headers)
            if status is not Status.FOUND:
                return status, fields, note
            user = root

    fields = {"scope": "Public account on this instance; ownership is unverified"}
    for key in (
        "id",
        "username",
        "login",
        "name",
        "display_name",
        "full_name",
        "bio",
        "note",
        "created_at",
        "published",
    ):
        value = user.get(key)
        if isinstance(value, str) or type(value) is int:
            fields[key] = value
    return Status.FOUND, fields, None
