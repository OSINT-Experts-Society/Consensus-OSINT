"""Shared retained Discourse profile contract; synthetic evidence, not live availability."""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from .models import Status

# Exact maintained forum scopes; these are not parent-product account systems.
FORUM_HOSTS = {
    'us-user-creative-blender_artists': 'blenderartists.org',
    'us-user-dev-fedora': 'discussion.fedoraproject.org',
    'us-user-dev-gitlab_forum': 'forum.gitlab.com',
    'us-user-dev-gnome': 'discourse.gnome.org',
    'us-user-dev-huggingface_forum': 'discuss.huggingface.co',
    'us-user-dev-jenkins': 'community.jenkins.io',
    'us-user-dev-kde': 'discuss.kde.org',
    'us-user-dev-kicad': 'forum.kicad.info',
    'us-user-dev-nixos': 'discourse.nixos.org',
    'us-user-dev-opensearch': 'forum.opensearch.org',
    'us-user-community-discourse_meta': 'meta.discourse.org',
    'us-user-community-ghost_forum': 'forum.ghost.org',
    'us-user-community-ubuntu_mate': 'ubuntu-mate.community',
    'us-user-dev-f_droid': 'forum.f-droid.org',
    'us-user-dev-hashicorp_discuss': 'discuss.hashicorp.com',
    'us-user-dev-kotlin_discuss': 'discuss.kotlinlang.org',
    'us-user-dev-python_discuss': 'discuss.python.org',
    'us-user-dev-rust_users': 'users.rust-lang.org',
    'us-user-community-openai_community': 'community.openai.com',
    'us-user-dev-julialang': 'discourse.julialang.org',
    'us-user-community-jupyter_forum': 'discourse.jupyter.org',
    'us-user-community-mozilladiscourse': 'discourse.mozilla.org',
    'us-user-dev-elixir_forum': 'forum.elixirforum.com',
    'us-user-dev-arduino': 'forum.arduino.cc',
    "rule-arduino": "forum.arduino.cc",
}


def prefer_profile_module(module, site) -> bool:
    """Prefer the maintained JSON binding only for equivalent public forum routes."""
    host = FORUM_HOSTS.get(module.id)
    source = "rules" if module.id == "rule-arduino" else "user-scanner"
    if not host or module.kind != "username" or module.source != source:
        return False
    base = f"https://{host}/u/{{username}}"
    if module.url_main != base or site.id_type != "username" or site.method != "GET":
        return False
    if site.url not in {base, base + "/summary"} or site.url_probe not in {None, base + ".json", base + "/summary.json"}:
        return False
    if site.payload or any(key.lower() not in {"user-agent", "accept", "accept-language"} for key in site.headers):
        return False
    return True


def profile_outcome(response, query: str) -> tuple[Status, dict, str | None]:
    """Only a matching username or an explicit missing-user payload is definitive."""
    code = response.status_code
    if code == 429:
        return Status.RATE_LIMITED, {}, "Discourse rate limited the request (HTTP 429)"
    if code in (401, 403, 406, 407, 418, 451) or response.headers.get("cf-mitigated", "").lower() == "challenge":
        return Status.BLOCKED, {}, f"Discourse access blocked or challenged (HTTP {code})"
    if code not in (200, 404):
        return (Status.ERROR if code >= 500 else Status.UNKNOWN), {}, f"Discourse HTTP {code}; profile availability is unknown"
    try:
        data = response.json()
    except (ValueError, TypeError):
        return Status.UNKNOWN, {}, "Discourse response is not valid JSON"
    if not isinstance(data, dict):
        return Status.UNKNOWN, {}, "Discourse response is not an object"
    user = data.get("user")
    if code == 404:
        errors = data.get("errors", [])
        missing = data.get("error_type") == "not_found"
        if data.get("error_type") is None and isinstance(errors, list):
            missing = any(isinstance(error, str) and "not be found" in error.casefold() for error in errors)
        if missing and user is None:
            return Status.NOT_FOUND, {}, None
        return Status.UNKNOWN, {}, "Discourse 404 response lacks unambiguous missing-user evidence"
    if data.get("errors") or data.get("error_type"):
        return Status.UNKNOWN, {}, "Discourse response contains an error"
    if not isinstance(user, dict) or not isinstance(user.get("username"), str) or not user["username"]:
        return Status.UNKNOWN, {}, "Discourse response lacks a typed profile username"
    if user["username"].lower() != query.lower():
        return Status.UNKNOWN, {}, "Returned Discourse username does not match the requested username"
    return Status.FOUND, user, None


def decoded_profile_outcome(code, data, query, headers):
    """Evaluate already-decoded JSON without replaying wire compression headers."""
    from types import SimpleNamespace

    import httpx

    response = SimpleNamespace(status_code=code, headers=httpx.Headers(headers), json=lambda: data)
    return profile_outcome(response, query)


def _fields(user: dict, style: str, profile_url: str) -> tuple[dict, dict]:
    extra, media = {}, {}
    if style == "rich":
        for source, target in (("name", "name"), ("title", "title"), ("location", "location"), ("created_at", "joined")):
            if isinstance(user.get(source), str) and user[source]:
                extra[target] = user[source]
        for sources, target in ((("website", "website_name"), "website"), (("bio_raw", "bio_cooked"), "bio")):
            for source in sources:
                if isinstance(user.get(source), str) and user[source]:
                    extra[target] = user[source]
                    break
        for source, target in (("trust_level", "trust_level"), ("badge_count", "badges")):
            if type(user.get(source)) is int:
                extra[target] = str(user[source])  # Retain this family's scalar schema.
    elif style == "standard":
        for source, target in (("name", "name"), ("username", "username"), ("title", "title"),
                               ("last_posted_at", "last_posted"), ("last_seen_at", "last_seen"), ("created_at", "registered")):
            if isinstance(user.get(source), str) and user[source]:
                extra[target] = user[source]
        if type(user.get("id")) is int and user["id"]:
            extra["id"] = user["id"]
    elif style == "mozilla":
        for source in ("name", "title", "created_at"):
            if isinstance(user.get(source), str) and user[source]:
                extra[source] = user[source]
        for source, target in (("trust_level", "trust_level"), ("profile_view_count", "profile_views")):
            if type(user.get(source)) is int:
                extra[target] = user[source]
    if style in ("rich", "standard"):
        template = user.get("avatar_template")
        if isinstance(template, str) and template:
            try:
                avatar = urljoin(profile_url, template.replace("{size}", "240" if style == "rich" else "120"))
                parsed = urlsplit(avatar)
                if parsed.scheme in ("http", "https") and parsed.hostname:
                    media["avatar"] = avatar
            except ValueError:
                pass
    return extra, media


def lookup(query: str, url: str, profile_url: str, *, style: str, **request_options):
    """Use the retained transport and preserve each forum's declared field schema."""
    from ..vendor.user_scanner.core.orchestrator import make_request
    from ..vendor.user_scanner.core.result import Result

    try:
        response = make_request(url, **request_options)
        status, user, reason = profile_outcome(response, query)
        if status is Status.NOT_FOUND:
            return Result.available(url=profile_url)
        if status is not Status.FOUND:
            return Result.error(reason, url=profile_url)
        extra, media = _fields(user, style, profile_url)
        return Result.taken(url=profile_url, extra=extra, media=media)
    except Exception as exc:
        return Result.error(exc, url=profile_url)


def catalogue_outcome(code, text, query, headers):
    """Strict JSON forum evidence for the retained Twitter Community catalogue."""
    import json

    from .email_validation import _unique_object
    from .mailbox_contracts import http_issue
    from .named_user_contracts import _text, _url
    from .provider_contracts import has_service_error

    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, {}, reason
    try:
        root = json.loads(text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Status.UNKNOWN, {}, "Invalid forum profile JSON"
    user = root.get("user") if isinstance(root, dict) else None
    if (not isinstance(root, dict) or has_service_error(root) or not isinstance(user, dict)
            or has_service_error(user) or type(user.get("id")) is not int or user["id"] <= 0):
        return Status.UNKNOWN, {}, "No successful typed forum identity"
    status, _, reason = decoded_profile_outcome(code, root, query, headers)
    if status is not Status.FOUND:
        return status, {}, reason
    extra = {"username": user["username"], "user_id": user["id"],
             "scope": "Twitter Community forum profile; not a current X account or proof of ownership"}
    for key in ("name", "title", "created_at", "last_seen_at"):
        if value := _text(user.get(key)):
            extra[key] = value
    template = user.get("avatar_template")
    if _text(template) and "\\" not in template:
        try:
            avatar = _url(urljoin("https://twittercommunity.com/", template.replace("{size}", "120")))
        except ValueError:
            avatar = None
        if avatar:
            extra["media"] = {"avatar": avatar}
    return Status.FOUND, extra, None
